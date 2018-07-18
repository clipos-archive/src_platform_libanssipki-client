# -*- coding: utf-8 -*-
# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright © 2013-2018 ANSSI. All Rights Reserved.

import anssipki
import sqlite3
import os
from datetime import datetime
from time import time
from base64 import b64encode, b64decode
from CACertificate import CACertificate
from Certificate import Certificate
from Conf import Conf
initScript = ["\
CREATE TABLE config (\
name 		VARCHAR(50) UNIQUE NOT NULL,\
value		VARCHAR(255) NOT NULL\
)",
"CREATE TABLE certificate ( \
id 			INTEGER PRIMARY KEY, \
cryptoID 		INTEGER NOT NULL, \
name			VARCHAR(255), \
cache_dn		VARCHAR(255), \
cache_not_before	INTEGER NOT NULL, \
cache_not_after	INTEGER NOT NULL, \
cache_sign_algo	VARCHAR(255), \
issuer_ca_id	INTEGER, \
keyGeneratedOnSmartCard	BOOLEAN DEFAULT(0), \
revoked				BOOLEAN DEFAULT(0), \
revocationTime		INTEGER DEFAULT NULL, \
revocationReason	VARCHAR(255) DEFAULT NULL \
)"	,
"CREATE TABLE ca ( \
id 			INTEGER PRIMARY KEY,\
certificate_id INTEGER,	\
sn_count		INTEGER DEFAULT(0),\
root			BOOLEAN DEFAULT(0), \
FOREIGN KEY (certificate_id) REFERENCES certificate(id) \
)",
"CREATE TABLE crl (\
id 			INTEGER PRIMARY KEY,\
ca_id INTEGER NOT NULL,\
data TEXT NOT NULL,\
lastUpdate	VARCHAR(255),\
nbRevoked INTEGER NOT NULL, \
FOREIGN KEY (ca_id) REFERENCES ca(id)\
)",
"CREATE TABLE actions (\
action_id		INTEGER NOT NULL,\
object_id		INTEGER NOT NULL,\
object_type		INTEGER NOT NULL,\
time			INTEGER NOT NULL,\
message			INTEGER NOT NULL\
)",
"INSERT INTO config (name, value) VALUES \
('cryptoIDCount', '0')"
]


logObjectID = {
	"CACertificate" : 1,
	"Certificate" : 2,
	"CRL" : 3
}

logActionID = {
	"Signature" : 1,
	"Revokation" : 2,
	"Renew" : 3,
	"CRLSignature" : 4
}

def dictFactory(cursor, row):
	d = {}
	for idx, col in enumerate(cursor.description):
		d[col[0]] = row[idx]
	return d

class DBHelper():
	instance = None

	def __init__(self, conn):
		self.conn = conn

	def __del__(self):
		self.conn.close()

	@staticmethod
	def getInstance():
		if not DBHelper.instance:
			db = "%s/%s.db" % (Conf.getValue("DB_DIR"), Conf.getValue("PKI_NAME"))
			if not os.path.exists(db):
				print "Creating new database for %s." % Conf.getValue("PKI_NAME")

			DBHelper.open(db)
		return DBHelper.instance

	@staticmethod
	def open(dbfile):
		if not os.path.isfile(dbfile):
			conn = sqlite3.connect(dbfile)
			conn.row_factory = dictFactory
			c = conn.cursor()
			for query in initScript:
				c.execute(query)
			conn.commit()
		else:
			conn = sqlite3.connect(dbfile)
			conn.row_factory = dictFactory
		DBHelper.instance = DBHelper(conn)

	@staticmethod
	def close():
		if DBHelper:
			del DBHelper.instance
		DBHelper.instance = None

	def logAction(self, actionId, objectType, objectId, message):
		cur = self.conn.cursor()
		cur.execute(
			"INSERT INTO actions(action_id, object_type, object_id, time, message) VALUES (?,?,?,?,?)",
			[actionId, objectType, objectId, time(), message]
			)
		self.conn.commit()

	def getCertLogActions(self, certID):
		cur = self.conn.cursor()
		cur.execute(
			"SELECT action_id, time, message FROM actions WHERE object_id=? AND (object_type=? OR object_type=?)",
			[certID, logObjectID["CACertificate"], logObjectID["Certificate"]]
			)
		logs = []
		for l in cur.fetchall():
			dt = datetime.fromtimestamp(l["time"])
			logs.append(dt.strftime("%c") + " : " + l["message"])
		return logs

	def getLogActions(self):
		cur = self.conn.cursor()
		cur.execute("SELECT action_id, time, message FROM actions WHERE 1 ORDER BY time")
		logs = []
		for l in cur.fetchall():
			dt = datetime.fromtimestamp(l["time"])
			logs.append(dt.strftime("%c") + " : " + l["message"])
		return logs

	def logSignature(self, cacert, newcert):
		msg = ""
		if not newcert:
			msg = "%s has been self-signed" % cacert.getCacheDN()
		else:
			msg = "%s has signed certificate %s" % (cacert.getCacheDN(), newcert.getCacheDN())
		if Conf.getValue("VERBOSE") == True:
			print msg
		self.logAction(logActionID["Signature"], logObjectID["CACertificate"], cacert.getDbCertID(),
			msg)

	def logCRLSignature(self, cacert, crl):
		msg = "%s has signed a CRL" % (cacert.getCacheDN())
		if Conf.getValue("VERBOSE") == True:
			print msg
		self.logAction(logActionID["CRLSignature"], logObjectID["CACertificate"], cacert.getDbCertID(),
			msg)


	def logRevocation(self, cert):
		msg = "%s has been revoked" % (cert.getCacheDN())
		if Conf.getValue("VERBOSE") == True:
			print msg
		self.logAction(logActionID["Revokation"], logObjectID["Certificate"], cert.getDbCertID(),
			msg)


	def getSelfSignedCertificateList(self):
		cur = self.conn.cursor()
		cur.execute("SELECT id, name, cache_dn, cache_not_before, cache_not_after, \
						cache_sign_algo, cryptoID, issuer_ca_id, keyGeneratedOnSmartCard, \
						revoked, revocationTime, revocationReason \
						FROM certificate WHERE issuer_ca_id=0 AND revoked=0")
		certList = []
		for row in cur.fetchall():
			certList.append(Certificate().fromDB(row))
		return certList

	def getRootCAList(self):
		cur = self.conn.cursor()
		rootCAList = []
		caSql = "SELECT id, sn_count, certificate_id FROM ca WHERE root=1"
		certSql = "SELECT name, cache_dn, cache_not_before, cache_not_after, \
					cache_sign_algo, keyGeneratedOnSmartCard, \
					revoked, revocationTime, revocationReason, \
					issuer_ca_id, cryptoID, id FROM certificate WHERE id=? AND revoked=0"
		cur.execute(caSql)
		for cacertRow in cur.fetchall():
			cur.execute(certSql, [str(cacertRow["certificate_id"])])
			certRow = cur.fetchone()
			if certRow != None:
				rootCAList.append(CACertificate().fromDB(cacertRow, certRow))
		return rootCAList

	def getChildren(self, ca):
		certList = []
		cur = self.conn.cursor()
		cur.execute("SELECT name, cache_dn, cache_not_before, cache_not_after, \
					cache_sign_algo, keyGeneratedOnSmartCard, \
					revoked, revocationTime, revocationReason, \
					issuer_ca_id, cryptoID, id FROM certificate WHERE issuer_ca_id=? AND id<>? AND revoked=0",
					(ca.getDbCaID(), ca.getDbCertID()))
		for certRow in cur.fetchall():
			cur2 = self.conn.cursor()
			cur2.execute("SELECT id, sn_count, certificate_id FROM ca WHERE certificate_id=?",
						 [certRow["id"]])
			cacertRow = cur2.fetchone()
			if cacertRow:
				certList.append(CACertificate().fromDB(cacertRow, certRow))
			else:
				certList.append(Certificate().fromDB(certRow))
		return certList

	def getSubCas(self, ca):
		certList = []
		cur = self.conn.cursor()
		cur.execute("SELECT name, cache_dn, cache_not_before, cache_not_after, \
					cache_sign_algo, keyGeneratedOnSmartCard, \
					revoked, revocationTime, revocationReason, \
					issuer_ca_id, cryptoID, id FROM certificate WHERE issuer_ca_id=? AND id<>? AND revoked=0",
					(ca.getDbCaID(), ca.getDbCertID()))
		for certRow in cur.fetchall():
			cur2 = self.conn.cursor()
			cur2.execute("SELECT id, sn_count, certificate_id FROM ca WHERE certificate_id=?",
						 [certRow["id"]])
			cacertRow = cur2.fetchone()
			if cacertRow:
				certList.append(CACertificate().fromDB(cacertRow, certRow))
		return certList


	def getCertificateFromDN(self, dn, ca=None):
		if not ca:
			cur = self.conn.cursor()
			cur.execute("SELECT id FROM certificate WHERE cache_dn=? AND revoked=0", [dn])
			certRow = cur.fetchone()
			if certRow:
				return self.getCertificateFromID(int(certRow["id"]))
			else:
				return None
		else:
			cur = self.conn.cursor()
			cur.execute("SELECT id FROM certificate WHERE cache_dn=? AND revoked=0 AND issuer_ca_id=?",
				[dn, ca.getDbCaID()])
			certRow = cur.fetchone()
			if certRow:
				return self.getCertificateFromID(int(certRow["id"]))

			for subCA in self.getSubCas(ca):
				found = self.getCertificateFromDN(dn, subCA)
				if found:
					return found

			return None


	def getCertificateFromName(self, name):
		cur = self.conn.cursor()
		cur.execute("SELECT id FROM certificate WHERE name=? AND revoked=0", [name])
		certRow = cur.fetchone()
		if certRow:
			return self.getCertificateFromID(int(certRow["id"]))
		else:
			return None

	def getCertificateFromID(self, certId):
		cur = self.conn.cursor()
		cur.execute("SELECT name, cache_dn, \
					cache_not_before, cache_not_after, cache_sign_algo, \
					issuer_ca_id, keyGeneratedOnSmartCard, \
					revoked, revocationTime, revocationReason, \
					cryptoID, id FROM certificate WHERE id=? AND revoked=0",
					[certId])
		certRow = cur.fetchone()
		if not certRow:
			return None

		cur.execute(
			"SELECT id, sn_count FROM ca WHERE certificate_id=?", [certId])
		cacertRow = cur.fetchone()

		if cacertRow:
			return CACertificate().fromDB(cacertRow, certRow)
		else:
			return Certificate().fromDB(certRow)


	def getCAFromID(self, caId):
		cur = self.conn.cursor()
		cur.execute(
			"SELECT certificate_id FROM ca WHERE id=?", [caId])
		cacertRow = cur.fetchone()
		if not cacertRow:
			return None
		else:
			return self.getCertificateFromID(cacertRow['certificate_id'])


	def newCryptoID(self):
		cur = self.conn.cursor()
		cur.execute("SELECT value FROM config WHERE name='cryptoIDCount'")
		cryptoIDCount = cur.fetchone()["value"]
		cur.execute("UPDATE config SET value=? WHERE name='cryptoIDCount'",
			[str(int(cryptoIDCount) + 1)])
		self.conn.commit()
		return int(cryptoIDCount)

	def updateCACertificateSerialNumberCount(self, cacert):
		cur = self.conn.cursor()
		cur.execute("UPDATE ca SET sn_count=? WHERE ID=?",
				[cacert.getSerialNumberCount(), cacert.getDbCaID()])
		self.conn.commit()

	def saveCACertificate(self, cacert):
		cur = self.conn.cursor()
		if cacert.getDbCaID():
			cur.execute("UPDATE ca SET certificate_id=?, root=?, sn_count=? WHERE ID=?",
				[cacert.getDbCertID(), cacert.isSelfSigned(), cacert.getSerialNumberCount(),
				 cacert.getDbCaID()])
		else:
			cur.execute("INSERT INTO ca(certificate_id, root, sn_count) VALUES (?,?,?)",
				[cacert.getDbCertID(), cacert.isSelfSigned(), cacert.getSerialNumberCount()])
			cacert.setDbCaID(cur.lastrowid)
		self.conn.commit()
		return cacert

	def saveCertificate(self, cert):
		cur = self.conn.cursor()
		if cert.getDbCertID():
			cur.execute("UPDATE certificate SET cryptoID=?, name=?, cache_dn=?, \
				cache_not_before=?, cache_not_after=?, cache_sign_algo=?, \
				issuer_ca_id=?, keyGeneratedOnSmartCard=? WHERE ID=?",
				[cert.getCryptoID(), cert.getName(), cert.getCacheDN(),
				 cert.getCacheNotBefore(), cert.getCacheNotAfter(),
				 cert.getCacheSignAlgo(), cert.getDbIssuerCaID(),
				 cert.hasKeyGeneratedOnSmartCard(), cert.getDbCertID()])
		else:
			cur.execute("INSERT INTO certificate(cryptoID, name, cache_dn, cache_not_before, \
				cache_not_after, cache_sign_algo, issuer_ca_id, keyGeneratedOnSmartCard) \
				VALUES (?,?,?,?,?,?,?,?)",
				[cert.getCryptoID(), cert.getName(), cert.getCacheDN(),
				 cert.getCacheNotBefore(), cert.getCacheNotAfter(),
				 cert.getCacheSignAlgo(), cert.getDbIssuerCaID(),
				 cert.hasKeyGeneratedOnSmartCard()])
			cert.setDbCertID(cur.lastrowid)
		self.conn.commit()

	def revokeCertificate(self, cert, time, reason):
		cur = self.conn.cursor()
		cur.execute("UPDATE certificate SET revoked=1, revocationTime=?, \
			revocationReason=? WHERE ID=?",
			[time, reason, cert.getDbCertID()])
		self.conn.commit()

	def getRevokedCertificates(self, issuer):
		certList = []
		cur = self.conn.cursor()
		cur.execute("SELECT name, cache_dn, cache_not_before, cache_not_after, \
					cache_sign_algo, keyGeneratedOnSmartCard, \
					revoked, revocationTime, revocationReason, \
					issuer_ca_id, cryptoID, id FROM certificate WHERE issuer_ca_id=? AND id<>? AND revoked=1",
					(issuer.getDbCaID(), issuer.getDbCertID()))
		for certRow in cur.fetchall():
			cur2 = self.conn.cursor()
			cur2.execute("SELECT id, sn_count, certificate_id FROM ca WHERE certificate_id=?",
						 [certRow["id"]])
			cacertRow = cur2.fetchone()
			if cacertRow:
				certList.append(CACertificate().fromDB(cacertRow, certRow))
			else:
				certList.append(Certificate().fromDB(certRow))
		return certList

	def saveCrl(self, crlDer, lastUpdate, nbRevoked, issuer):
		cur = self.conn.cursor()
		cur.execute("INSERT INTO crl(data, lastUpdate, ca_id, nbRevoked) VALUES (?,?,?,?)",
				[b64encode(crlDer), lastUpdate, issuer.getDbCaID(), nbRevoked])
		self.conn.commit()

	def save(self, obj):
		if type(obj) == CACertificate:
			self.saveCertificate(obj)
			self.saveCACertificate(obj)
		elif type(obj) == Certificate:
			self.saveCertificate(obj)
		else:
			raise Exception("DBHelper:save : Mauvais paramètre obj")


	def changeCertificateInternalName(self, cert, name):
		cur = self.conn.cursor()
		cur.execute("UPDATE certificate SET name=? WHERE id=?", [name, cert.getDbCertID()])
		self.conn.commit()
