# -*- coding: utf-8 -*-
# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright © 2013-2018 ANSSI. All Rights Reserved.

import anssipki
from DBHelper import DBHelper
from CACertificate import CACertificate
from Certificate import Certificate
from Conf import Conf
from Validate import ValidateTBS

class CSR(object):
	"""
		Class haut niveau représentant une requête de certification.
		Peut-être auto-signé pour générer un nouveau certificat (ou certificat d'AC).
		Ou peut-être passé à un CACertificate pour une demande de signature.
	"""

	def __init__(self, dn, ca):
		self.x509Req = anssipki.newX509Request(dn)

		self.keyType = None
		self.keyLength = None

		self.cryptoID = None
		self.hPrivateKey = anssipki.CK_INVALID_HANDLE
		self.hPublicKey = anssipki.CK_INVALID_HANDLE

		self.generateKeyOnSmartCard = False
		self.label = Conf.getLabel()
		self.smartCardP11Helper = None

		if ca:
			self.x509Req.setCA()
			self.x509Req.setKeyUsage(anssipki.CRLSign)
			self.x509Req.setKeyUsage(anssipki.KeyCertSign)

	def setKeyOptions(self, keyType, keyLength, generateKeyOnSmartCard = False):
		"""Mets à jour les informations pour la génération du bi-clé."""
		self.keyType = keyType
		self.keyLength = keyLength
		self.generateKeyOnSmartCard = generateKeyOnSmartCard
		if self.generateKeyOnSmartCard:
			self.label = Conf.getLabel(anssipki.USAGE_SIGNATURE)
		
	def setKeyUsage(self, ku):
		"""Ajoute un nouveau KeyUsage."""
		self.x509Req.setKeyUsage(ku)

	def setExtendedKeyUsage(self, eku):
		"""Ajoute un nouveau ExtendedKeyUsage."""
		self.x509Req.setExtendedKeyUsage(eku)

	def addSubjectAltName(self, sanType, sanValue):
		"""Ajoute un nouveau subjectAltName"""
		if sanType == anssipki.SAN_Email:
			self.x509Req.addSubjectAltNameEmail(sanValue)
		if sanType == anssipki.SAN_DNS:
			self.x509Req.addSubjectAltNameDNS(sanValue)
		if sanType == anssipki.SAN_IPAddress:
			self.x509Req.addSubjectAltNameIP(sanValue)
		if sanType == anssipki.SAN_URI:
			self.x509Req.addSubjectAltNameURI(sanValue)

	def addCertificatePolicy(self, OID, CPS):
		"""Ajoute une nouvelle strategie de certification."""
		self.x509Req.addCertificatePolicy(OID, CPS)

	def addOSSLextension(self, content):
		"""Utilise la fonction de parsing de configuration d'OpenSSL pour générer une ou plusieurs extensions."""
		self.x509Req.addOSSLextension(content)

	def getCryptoID(self):
		"""Retourne l'ID crypto dans la ressource P11"""
		return self.cryptoID

	def generateKey(self):
		"""Génère le bi-clé dans la ressource P11. (Voir setKeyOptions)"""
		self.cryptoID = DBHelper.getInstance().newCryptoID()
		sensitiveKeys = self.x509Req.isCA()

		p11Helper = None
		if self.generateKeyOnSmartCard:
			p11Helper = anssipki.P11Helper.connect(Conf.getValue("PKCS11_SMARTCARD_MODULE"),
												Conf.getValue("PKCS11_SMARTCARD_PIN"),
												Conf.getValue("PKCS11_SMARTCARD_LABEL"),
												Conf.getValue("PKCS11_SMARTCARD_SLOT") != None,
												Conf.getValue("PKCS11_SMARTCARD_SLOT"))
			self.smartCardP11Helper = p11Helper
			if not p11Helper:
				raise Exception('Error loading PKCS#11 ressource.')
			# Flag specific à SWIG. Une fois mis à true, l'objet C++ réferencé
			# est détruit lorsque ce dernier est récupéré par le GC.
			self.smartCardP11Helper.thisown = True
		else:
			p11Helper = anssipki.P11Helper.getInstance()


		if self.keyType == anssipki.KPA_RSA:
			usage = anssipki.USAGE_SIGNATURE
			self.hPublicKey, self.hPrivateKey = p11Helper.generateRSAKeyPair(self.keyLength,
											 self.cryptoID,
											 sensitiveKeys,
											 self.label,
											 usage)
		else:
			raise Exception('KeyType not implemented')

		self.x509Req.setPublicKey(p11Helper.extractPublicKey(self.hPublicKey))


	def selfSign(self, notBefore, notAfter, signAlgorithm):
		"""Signe la CSR avec sa propre clé privée et retourne le Certificate/CACertificate généré."""

		signAlgorithmNID = anssipki.SignAlgoStrToNID(signAlgorithm)
		if signAlgorithmNID == 0:
			raise Exception('Invalid signAlgorithm %s' % signAlgorithm)

		# Génère le bi-clé dans le HSM
		self.generateKey()

		# Génère un serialNumber de 20 octets via la ressource P11.
		serialNumber = anssipki.generateSerialNumber()

		# Construction du bloc TBS.
		tbs = anssipki.X509Tbs.FromX509Req(self.x509Req, notBefore, notAfter,
										   signAlgorithmNID, serialNumber, None)

		if Conf.getValue("SIGNATURE_CONFIRMATION"):
			print tbs.dump()

			validation = None
			while (validation != 'y' and validation != 'n'):
				validation = raw_input("Are you sure to sign this request [y/n] :")
				if validation == 'y':
					pass
				elif validation == 'n':
					raise Exception("Certificate signature canceled")

		x509_check = Conf.getValue("X509_CHECK")
		if x509_check != None:
			if not ValidateTBS(x509_check, tbs.toDER()):
				raise Exception("Certificate validation Failed.")

		# Récupère le mechanism P11 pour la signature
		mechanism = anssipki.SignAlgoStrToP11Mech(signAlgorithm)

		# Signature du bloc TBS avec la clé privée de l'AC.
		signature = anssipki.P11Helper.getInstance().sign(tbs.toDER(), mechanism, self.hPrivateKey)

		# Création du nouveau certificat X509 avec la signature générée.
		x509Cert = anssipki.X509Cert.FromX509Tbs(tbs, signature)

		# Sauvegarde du certificat X509 dans la ressource P11
		anssipki.P11Helper.getInstance().writeCertificate(x509Cert, self.cryptoID, self.label)
		if self.generateKeyOnSmartCard:
			self.smartCardP11Helper.writeCertificate(x509Cert, self.cryptoID, self.label)

		# Création de l'object Certificate/CACertificate associé.
		if x509Cert.isCA():
			cert = CACertificate().fromCSR(self, x509Cert, None)
		else:
			cert = Certificate().fromCSR(self, x509Cert, None)

		# Sauvegarde du certificat dans la base de données.
		DBHelper.getInstance().save(cert)

		# Journalisation de l'action de signature
		DBHelper.getInstance().logSignature(cert, None)

		return cert
