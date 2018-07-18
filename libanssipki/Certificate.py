# -*- coding: utf-8 -*-
# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright © 2013-2018 ANSSI. All Rights Reserved.

import re
import anssipki
import DBHelper
from Conf import Conf
import time

class Certificate(object):
	"""
		Class haut niveau vers les certificats construits par l'anssipki.
		Elle contient les informations mises en cache dans la base de données mais
		peut aussi accéder aux objets P11 lui correspondant (Certificat X509, Handles vers
		le bi-clé.)
	"""
	def __init__(self):
		# Nom interne du certificat
		self.internalName = None
		# DN du certificat (Cache SQLite)
		self.cacheDN = None
		# Debut de validité (Cache SQLite)
		self.cacheNotBefore = None
		# Fin de validité (Cache SQLite)
		self.cacheNotAfter = None
		# Algorithme utilisé pour la signature (Cache SQLite)
		self.cacheSignAlgo = None
		# ID du certificat dans la base de données
		self.dbCertId = None
		# ID du certificat et de son bi-clé dans la base de données
		self.cryptoID = None
		# ID de l'AC parente dans la base de données (0 = Pas d'AC parente)
		self.dbIssuerCaId = 0
		# Vrai si les clés ont été générées sur une smartcard (et donc pas présente dans le softhsm)
		self.keyGeneratedOnSmartCard = False

		self.revoked = False
		self.revocationReason = None
		self.revocationTime = None

		# Handlers vers les ressources P11
		self.hPrivateKey = anssipki.CK_INVALID_HANDLE
		self.hPublicKey = anssipki.CK_INVALID_HANDLE
		self.hCertificate = anssipki.CK_INVALID_HANDLE

		# AC parente
		self.issuerCA = None

		# Certificat X509
		self.x509 = None

	def fromCSR(self, csr, cert, issuer=None):
		"""
			Construction d'un objet Certificat après une signature de CSR.
			Mets à jour les informations à enregistrer dans la base de données.
		"""
		self.cacheDN  = cert.getSubjectDNString()
		self.cacheNotBefore = cert.getNotBefore()
		self.cacheNotAfter = cert.getNotAfter()
		self.cacheSignAlgo = anssipki.SignAlgoNIDToStr(cert.getSignAlgoNID())
		self.cryptoID = csr.cryptoID
		self.hPrivateKey = csr.hPrivateKey
		self.hPublicKey = csr.hPublicKey
		self.hCertificate = anssipki.CK_INVALID_HANDLE
		self.x509 = cert
		self.keyGeneratedOnSmartCard = csr.generateKeyOnSmartCard
		if issuer:
			self.issuerCA = issuer
			self.dbIssuerCaId = issuer.getDbCaID()
		self.setInternalName()
		return self

	def fromDB(self, dbInfo):
		"""
			Construction d'un objet Certificat depuis les informations contenues dans
			la base de données.
		"""
		self.dbCertId = int(dbInfo['id'])
		self.cryptoID = int(dbInfo['cryptoID'])
		self.internalName = dbInfo['name'].encode('utf-8')
		self.cacheDN = dbInfo['cache_dn'].encode('utf-8')
		self.cacheNotBefore = dbInfo['cache_not_before'].encode('utf-8')
		self.cacheNotAfter = dbInfo['cache_not_after'].encode('utf-8')
		self.cacheSignAlgo = dbInfo['cache_sign_algo'].encode('utf-8')
		self.keyGeneratedOnSmartCard = bool(dbInfo['keyGeneratedOnSmartCard'])
		self.revoked = bool(dbInfo['revoked'])
		self.revocationReason = dbInfo['revocationReason']
		self.revocationTime = dbInfo['revocationTime']
		# dbInfo['issuer_ca_id'] = None si certificat auto-signé
		if dbInfo['issuer_ca_id']:
			self.dbIssuerCaId = int(dbInfo['issuer_ca_id'])
		else:
			self.dbIssuerCaId = None
		return self

	def setInternalName(self):
		"""
			Mets à jour le nom interne du certificat. Celui-ci est construit en
			fonction du "Subject" et des "SubjectAltName".
		"""
		reMatch = re.search("CN=([^,]+)" ,self.x509.getSubjectDNString())
		if reMatch and len(reMatch.groups()) > 0:
			self.internalName = reMatch.groups()[0]
		else:
			self.internalName = self.x509.getSubjectDNString()

	def isCA(self):
		return False

	def setDbCertID(self, dbCertId):
		self.dbCertId = dbCertId

	def getName(self):
		""" Retourne le nom interne du certificat"""
		return self.internalName

	def getDbCertID(self):
		""" Retourne l'ID du certificat dans la base de données"""
		return self.dbCertId

	def getDbIssuerCaID(self):
		""" Retourne l'ID de l'AC issuer dans la base de données. NULL si certificat auto-signé"""
		return self.dbIssuerCaId

	def getCacheDN(self):
		""" Retourne le DN mis en cache dans la base de données"""
		return self.cacheDN

	def getCacheNotBefore(self):
		""" Retourne le début de validité mis en cache dans la base de données"""
		return self.cacheNotBefore

	def getCacheNotAfter(self):
		""" Retourne la fin de validité mis en cache dans la base de données"""
		return self.cacheNotAfter

	def getCacheSignAlgo(self):
		""" Retourne l'algorithme de signaturemis en cache dans la base de données"""
		return self.cacheSignAlgo

	def getCryptoID(self):
		""" Retourne l'ID du certificat dans la ressource P11"""
		return self.cryptoID

	def getIssuerCa(self):
		""" Retourne le CACertificate correspondant à l'AC parente, NULL si certificat auto-signé"""
		if self.isSelfSigned():
			return None
		if self.issuerCA:
			return self.issuerCA
		self.issuerCA = DBHelper.DBHelper.getInstance().getCAFromID(self.getDbIssuerCaID())
		if self.issuerCA == None:
			raise Exception("Certificate::getIssuerCa : cannot access parent CA.")
		return self.issuerCA

	def getRootCa(self):
		""" Retourne le CACertificate correspondant à l'AC racine, NULL si certificat auto-signé"""
		if self.isSelfSigned():
			return None
		rootCA = self
		while not rootCA.isSelfSigned():
			rootCA = DBHelper.DBHelper.getInstance().getCAFromID(rootCA.getDbIssuerCaID())
			if not rootCA:
				raise Exception("Certificate::getRootCa : cannot access parent CA.")
		return rootCA

	def isSelfSigned(self):
		""" Retourne si le certificat est auto-signé."""
		return (self.issuerCA == None and
			(self.dbIssuerCaId == 0 or self.dbIssuerCaId == None))

	def hasKeyGeneratedOnSmartCard(self):
		""" Retourne vrai si le bi-clé à été généré sur uen smartcard"""
		return self.keyGeneratedOnSmartCard

	# FIXME Exception si on trouve plusieurs objets ...
	def fetchP11PrivateKeyHandle(self):
		if self.hPrivateKey == anssipki.CK_INVALID_HANDLE:
			objCount, self.hPrivateKey = anssipki.P11Helper.getInstance().getObjectHandleByID(
				anssipki.CKO_PRIVATE_KEY, self.getCryptoID())
	def fetchP11PublicKeyHandle(self):
		if self.hPublicKey == anssipki.CK_INVALID_HANDLE:
			objCount, self.hPublicKey = anssipki.P11Helper.getInstance().getObjectHandleByID(
				anssipki.CKO_PUBLIC_KEY, self.getCryptoID())
	def fetchP11CertificateHandle(self):
		if self.hCertificate == anssipki.CK_INVALID_HANDLE:
			objCount, self.hCertificate = anssipki.P11Helper.getInstance().getObjectHandleByID(
				anssipki.CKO_CERTIFICATE, self.getCryptoID())

	def getX509CertDER(self):
		""" Retourne le certificat X509 encodé en DER."""
		self.fetchP11CertificateHandle()
		return anssipki.P11Helper.getInstance().extractCertificate(self.hCertificate)

	def fetchX509Cert(self):
		""" Récupère le certificat X509 encodé en DER et crée le X509Cert associé."""
		der = self.getX509CertDER()
		self.x509 = anssipki.X509Cert.fromDER(der)
		# Flag specific à SWIG. Une fois mis à true, l'objet C++ réferencé par self.cert.x509
		# est détruit lorsque ce dernier est récupéré par le GC.
		self.x509.thisown = True

	def toCSR(self, signAlgo=None):
		"""
			Crée une CSR à partir d'un certificat.
			Utilisé lors du rattachement d'un certificat d'AC auto-signé à une autre AC.
		"""
		self.fetchP11PrivateKeyHandle()
		csr = anssipki.exportToCSR(self.hPrivateKey, self.getX509CertDER())
		return csr

	def extractToP12(self, password, chain):
		"""
			Retourne le certificat et sa clé privée protégé par un mot de passe au format P12.
			Si chain est à True, la chaine de certification est ajoutée au P12.
		"""
		chainList = []
		if chain == True:
			issuerCA = self.getIssuerCa()
			while issuerCA:
				chainList.append(issuerCA.getX509CertDER())
				issuerCA = issuerCA.getIssuerCa()
		self.fetchP11PrivateKeyHandle()
		return anssipki.extractToP12(self.hPrivateKey, self.getX509CertDER(), chainList, password, bool(Conf.getValue("USE_P11PROX")))

	def isRevoked(self):
		return self.revoked

	def getRevocationReason(self):
		return self.revocationReason

	def getRevocationTime(self):
		return self.revocationTime

	def revoke(self, reason):
		DBHelper.DBHelper.getInstance().revokeCertificate(self, int(time.time()), reason)
		DBHelper.DBHelper.getInstance().logRevocation(self)
