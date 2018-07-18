# -*- coding: utf-8 -*-
# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright © 2013-2018 ANSSI. All Rights Reserved.

from Certificate import Certificate
from Conf import Conf
from Validate import ValidateTBS
import DBHelper
import datetime

import anssipki

class CACertificate(Certificate):
	"""
		Class haut niveau pour un certificat d'AC.
		Hérite de la classe Certificate.
		Permet de signer des CSR.
	"""
	def __init__(self):
		Certificate.__init__(self)

		# ID du certificat d'AC dans la base de données
		self.dbCaId = None

		self.serialNumberCount = None

		self.X509Cert = None


	def fromCSR(self, csr, cert, issuer=None):
		"""Création d'un CACertificate à partir d'une CSR."""
		Certificate.fromCSR(self, csr, cert, issuer)
		self.serialNumberCount = 1
		self.X509Cert = None


		return self

	def fromDB(self, dbCAInfo, dbInfo):
		"""Création d'un CACertificate à partir des informations de la base de données."""
		Certificate.fromDB(self, dbInfo)
		self.dbCaId = int(dbCAInfo['id'])
		self.serialNumberCount = int(dbCAInfo['sn_count'])
		return self

	def isCA(self):
		return True

	def getDbCaID(self):
		"""Retourne l'ID du certificat d'AC dans la base de données"""
		return self.dbCaId

	def setDbCaID(self, dbCaId):
		"""Met à jour l'ID du certificat d'AC dans la base de données"""
		self.dbCaId = dbCaId

	def getSerialNumberCount(self):
		"""Retourne le compteur interne de l'AC pour la génération de numéro de série."""
		return self.serialNumberCount

	def generateSerialNumber(self):
		"""
			Génère un nouveau numéro de certificat de 20 octets avec 4 octets
			correspondant au compteur interne de l'AC et 16 octets aléatoire
			venant de la ressource P11.
		"""
		sn = anssipki.generateSerialNumberWithCounter(self.serialNumberCount)
		self.serialNumberCount = self.serialNumberCount + 1
		return sn

	def renewCertificate(self, certificat, notBefore, notAfter):
		"""
			Renouvellement de certificat pour une nouvelle periode
			Le certificat est récupéré depuis le stockage p11 au format DER
			et transformé en X509Cert. Ce denier est alors transformé en X509Tbs
			via la méthode renew pour une nouvelle demande de signature.
		"""

		signAlgorithm = certificat.getCacheSignAlgo()

		signAlgorithmNID = anssipki.SignAlgoStrToNID(signAlgorithm)
		if signAlgorithmNID == 0:
			raise Exception('Invalid signAlgorithm %s' % signAlgorithm)

		certificat.fetchX509Cert()

		tbs = certificat.x509.renew(notBefore, notAfter)

		signature = self.signTBS(tbs, signAlgorithmNID)

		# Création du nouveau certificat X509 avec la signature générée.
		x509Cert = anssipki.X509Cert.FromX509Tbs(tbs, signature)

		# Sauvegarde du certificat X509 dans la ressource P11
		anssipki.P11Helper.getInstance().writeCertificate(x509Cert, certificat.getCryptoID(), Conf.getValue("PKCS11_LABEL"))

		certificat.x509 = x509Cert

		# Sauvegarde du certificat dans la base de données.
		DBHelper.DBHelper.getInstance().save(certificat)

		# Mise à jour de l'AC dans la base de données (Compteur interne)
		DBHelper.DBHelper.getInstance().updateCACertificateSerialNumberCount(self)

		# Journalisation de l'action de signature
		DBHelper.DBHelper.getInstance().logSignature(self, certificat)

		return certificat


	def signCSR(self, csr, notBefore, notAfter, signAlgorithm = None):
		"""
			Méthode de signature de CSR.
			Génère le bi-clé dans la ressource P11, construit le bloc TBS et envoie l'action
			de signature à la ressource P11. Le nouveau certificat X509 est sauvegardé dans la
			ressource P11. L'objet CACertificate/Certificate associé est retourné.
		"""

		# Si aucun algorithme de signature n'est fournis, on utilise celui de l'AC.
		if signAlgorithm == None:
			signAlgorithm = self.cacheSignAlgo

		signAlgorithmNID = anssipki.SignAlgoStrToNID(signAlgorithm)
		if signAlgorithmNID == 0:
			raise Exception('Invalid signAlgorithm %s' % signAlgorithm)


		# Génère le bi-clé dans le HSM
		csr.generateKey()

		# Génère un serialNumber de 20 octets via le compteur internet et la ressource P11.
		serialNumber = self.generateSerialNumber()

		self.fetchX509Cert()

		# Construction du bloc TBS.
		tbs = anssipki.X509Tbs.FromX509Req(csr.x509Req, notBefore, notAfter,
										   signAlgorithmNID, serialNumber, self.x509)

		signature = self.signTBS(tbs, signAlgorithmNID)

		# Création du nouveau certificat X509 avec la signature générée.
		x509Cert = anssipki.X509Cert.FromX509Tbs(tbs, signature)

		
		# Sauvegarde du certificat X509 dans la ressource P11
		if csr.generateKeyOnSmartCard:
			label = Conf.getLabel(anssipki.USAGE_SIGNATURE)
		else:
			label = Conf.getLabel()
			
		anssipki.P11Helper.getInstance().writeCertificate(x509Cert, csr.getCryptoID(), label)
		if csr.generateKeyOnSmartCard:
			csr.smartCardP11Helper.writeCertificate(x509Cert, csr.getCryptoID(), label)

		if x509Cert.isCA():
			cert = CACertificate().fromCSR(csr, x509Cert, self)
		else:
			cert = Certificate().fromCSR(csr, x509Cert, self)

		# Sauvegarde du certificat dans la base de données.
		DBHelper.DBHelper.getInstance().save(cert)

		# Mise à jour de l'AC dans la base de données (Compteur interne)
		DBHelper.DBHelper.getInstance().updateCACertificateSerialNumberCount(self)

		# Journalisation de l'action de signature
		DBHelper.DBHelper.getInstance().logSignature(self, cert)

		return cert


	def signTBS(self, tbs, signAlgorithmNID):
		"""
			Méthode de signature de bloc TBS.
			Après récupération d'un handle vers la clé privée de l'AC,
			le bloc TBS est envoyé à la ressource PKCS#11 pour une demande
			de signature.
			Le certificat généré est alors sauvegardé dans la BDD locale
			et l'action est journalisée.
		"""

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
			if not ValidateTBS(x509_check, tbs.toDER(), self.getX509CertDER()):
				raise Exception("Certificate validation Failed.")


		# Récupère le mechanism P11 pour la signature
		mechanism = anssipki.SignAlgoNIDToP11Mech(signAlgorithmNID)

		# Récupération d'un Handle vers la clé privée de l'AC
		self.fetchP11PrivateKeyHandle()

		# Signature du bloc TBS avec la clé privée de l'AC.
		signature = anssipki.P11Helper.getInstance().sign(tbs.toDER(), mechanism, self.hPrivateKey)

		return signature



	def attachCA(self, der):
		"""
			Importe le certificat après signature d'une autre AC.
			Cette fonction n'est disponible que les certificat d'AC racine généré
			par l'anssipki dans un but de rattachement à une autre AC.
		"""

		x509cert = anssipki.X509Cert.fromDER(der)
		x509cert.thisown = True

		origx509cert = anssipki.X509Cert.fromDER(self.getX509CertDER())
		origx509cert.thisown = True

		if x509cert.getSubjectDNString() != origx509cert.getSubjectDNString():
			return False

		# FIXME SN peut avoir changé.
		# FIXME check public key

		anssipki.P11Helper.getInstance().writeCertificate(x509cert, self.getCryptoID(), Conf.getValue("PKCS11_LABEL"))

		return True


	def buildCRL(self):
		revokedCertificates =  DBHelper.DBHelper.getInstance().getRevokedCertificates(self)
		self.fetchX509Cert()

		signAlgorithm = Conf.getValue("CRL_SIGNALGO")
		nextUpdateNbDays = Conf.getValue("CRL_NEXT_UPDATE_DAYS_NB")

		signAlgorithmNID = anssipki.SignAlgoStrToNID(signAlgorithm)
		if signAlgorithmNID == 0:
			raise Exception('Invalid signAlgorithm %s' % signAlgorithm)

		crl = anssipki.X509Crl(self.x509, nextUpdateNbDays, signAlgorithmNID)
		crl.thisown = True

		for cert in revokedCertificates:
			cert.fetchX509Cert()
			crl.addRevokedCertificate(cert.x509.getSerialNumber(),
				datetime.datetime.fromtimestamp(cert.revocationTime).strftime("%y%m%d%H%M%SZ"))

		if Conf.getValue("SIGNATURE_CONFIRMATION"):
			print crl.dump()

			validation = None
			while (validation != 'y' and validation != 'n'):
				validation = raw_input("Are you sure to sign this request [y/n] :")
				if validation == 'y':
					pass
				elif validation == 'n':
					raise Exception("CRL signature canceled")

		# FIXME Not working yet
		# x509_check = Conf.getValue("X509_CHECK")
		# if x509_check != None:
		# 	if not ValidateTBS(x509_check, crl.toTbsDER(), self.getX509CertDER()):
		# 		raise Exception("Certificate validation Failed.")


		# Récupère le mechanism P11 pour la signature
		mechanism = anssipki.SignAlgoNIDToP11Mech(signAlgorithmNID)

		# Récupération d'un Handle vers la clé privée de l'AC
		self.fetchP11PrivateKeyHandle()

		# Signature du bloc TBS avec la clé privée de l'AC.
		signature = anssipki.P11Helper.getInstance().sign(crl.toTbsDER(), mechanism, self.hPrivateKey)

		# Ajout de la signature et génération de la CRL au format DER
		crl.setSignature(signature)
		crlDer = crl.toDER()

		# Sauvegarde de la crl dans la base de donnée.
		DBHelper.DBHelper.getInstance().saveCrl(crlDer,
				crl.getLastUpdate(),
				len(revokedCertificates), self)

		# Journalisation de l'action de création de CRL
		DBHelper.DBHelper.getInstance().logCRLSignature(self, crl)

		return crlDer
