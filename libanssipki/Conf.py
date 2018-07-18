# -*- coding: utf-8 -*-
# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright © 2013-2018 ANSSI. All Rights Reserved.

from ConfigParser import ConfigParser
import os, sys, io, anssipki

class Conf(object):

	conf = None
	sysPrefix = sys.argv[0][:(sys.argv[0].rindex('/') - len("/bin"))]
	sysConfDir = sysPrefix + "/etc/anssipki/"
	sysShareDir = sysPrefix + "/share/anssipki/"
	sysConfFile = os.environ['CONFFILE'] if 'CONFFILE' in os.environ else sysConfDir + "anssipki-p11.ini"
	userConfFileSample = sysConfDir + "anssipki.ini-sample"
	userConfDir = os.path.expanduser("~/.anssipki/")
	userConfFile = None if 'CONFFILE' in os.environ else userConfDir + "anssipki.ini"

	confValues = {
		"DB_DIR" : {
			"description" : "",
			"get" : lambda x,y,z: os.path.expanduser(ConfigParser.get(x,y,z)),
			"value" : None,
		},
		"TEMPLATES_DIR" : {
			"description" : "",
			"get" : lambda x,y,z: os.path.expanduser(ConfigParser.get(x,y,z)),
			"value" : [sysShareDir + "templates"],
			"multiple" : True
		},
		"PKI_NAME" : {
			"description" : "",
			"get" : ConfigParser.get,
			"value" : None,
		},
		"PKCS11_HOST_MODULE" : {
			"description" : "Path to the PKCS#11 library",
			"get" : ConfigParser.get,
			"value" : None
		},
		"PKCS11_HOST_SLOT" : {
			"description" : "Slot to use on PKCS#11 module",
			"get" : ConfigParser.getint,
			"value" : None,
			"optional" : True
		},
		"PKCS11_HOST_PIN" : {
			"description" : "PKCS#11 USER PIN code to access the token",
			"get" : ConfigParser.get,
			"value" : None,
			"ask" : True,
		},
		"PKCS11_HOST_LABEL" : {
			"description" : "Label to use in the PKCS#11 resource",
			"get" : ConfigParser.get,
			"value" : None
		},
		"PKCS11_SMARTCARD_MODULE" : {
			"description" : "Path to the PKCS#11 library",
			"get" : ConfigParser.get,
			"value" : None,
			"optional" : True
		},
		"PKCS11_SMARTCARD_SLOT" : {
			"description" : "Slot to use on PKCS#11 module",
			"get" : ConfigParser.getint,
			"value" : None,
			"optional" : True
		},
		"PKCS11_SMARTCARD_PIN" : {
			"description" : "PKCS#11 USER PIN code to access the token",
			"get" : ConfigParser.get,
			"value" : None,
			"ask" : True,
			"optional" : True
		},
		"PKCS11_SMARTCARD_LABEL" : {
			"description" : "Label to use in the PKCS#11 resource",
			"get" : ConfigParser.get,
			"value" : None,
			"optional" : True
		},
                "PKCS11_LABEL" : {
			"description" : "Label to use for PKCS#11 objects creation",
			"get" : ConfigParser.get,
			"value" : "ANSSIPKI"
		},
                "PKCS11_ENCRYPTION_LABEL" : {
			"description" : "Label to use for PKCS#11 objects creation for encryption usage",
			"get" : ConfigParser.get,
			"value" : None,
			"optional" : True
		},
		"PKCS11_SIGNATURE_LABEL" : {
			"description" : "Label to use for PKCS#11 objects creation for signature usage",
			"get" : ConfigParser.get,
			"value" : None,
			"optional" : True
		},
		"SIGNATURE_CONFIRMATION" : {
			"description" : "",
			"get" : ConfigParser.getboolean,
			"value" : True
		},
		"VERBOSE" : {
			"description" : "",
			"get" : ConfigParser.getboolean,
			"value" : False
		},
		"X509_CHECK" : {
			"description" : "",
			"get" : ConfigParser.get,
			"value" : None,
			"optional" : True
		},
		"USE_P11PROX" : {
			"description" : "",
			"get" : ConfigParser.getboolean,
			"value" : False
		},
		"CRL_SIGNALGO" : {
			"description" : "Set the signature algorithms for CRLs",
			"get" : ConfigParser.get,
			"value" : "SHA512RSA"
		},
		"CRL_NEXT_UPDATE_DAYS_NB" : {
			"description" : "Set the number of days between two updates",
			"get" : ConfigParser.getint,
			"value" : 30
		},
		"UNIQUE_DN" : {
			"description" : "Throw an error if a certificate with the same DN already exists",
			"get" : ConfigParser.get,
			"value" : "PARENT_CA",
			"optional" : True,
			"values" : ["ALL_CA", "PARENT_CA", "ALLOW_MULTIPLE"]
		},

	}

	@staticmethod
	def readConfFile(fp):
		conf = ConfigParser()
		conf.optionxform = str
		conf.readfp(fp)
		if 'CONFIGURATION' not in conf.sections():
			raise Exception("No section CONFIGURATION found")

		for (i,v) in conf.items('CONFIGURATION'):
			if i not in Conf.confValues:
				raise Exception("Invalid option %s" % i)
			else:
				try:
					val = Conf.confValues[i]["get"](conf, 'CONFIGURATION', i)
					if "values" in Conf.confValues[i] and val not in Conf.confValues[i]["values"]:
						raise Exception("Invalid value for option %s" % (i))
					if "multiple" in Conf.confValues[i] and Conf.confValues[i]["multiple"]:
						Conf.confValues[i]["value"].append(val)
					else:
						Conf.confValues[i]["value"] = val
				except Exception, e:
					raise Exception("Invalid value for option %s" % (i))


	@staticmethod
	def loadConf():
		#Récupération des options depuis les variables d'environnement
		for key in Conf.confValues:
			if key in os.environ:
				Conf.confValues[key]["value"] = os.environ[key]

		if not os.path.exists(Conf.userConfDir):
			os.makedirs(Conf.userConfDir)
		if not os.path.exists(Conf.userConfDir + "templates"):
			os.makedirs(Conf.userConfDir + "templates")
		if not os.path.exists(Conf.userConfDir + "databases"):
			os.makedirs(Conf.userConfDir + "databases")
		if Conf.userConfFile:
			if not os.path.exists(Conf.userConfFile):
				with open(Conf.userConfFileSample, "r") as samplefp:
					with open(Conf.userConfFile, "w") as fp:
						fp.write(samplefp.read())

		#Récupération des options depuis le fichier de configuration
		with open(Conf.sysConfFile, "r") as fp:
			Conf.readConfFile(fp)
		if Conf.userConfFile:
			with open(Conf.userConfFile, "r") as fp:
				Conf.readConfFile(fp)

		for i in Conf.confValues:
			if Conf.confValues[i]["value"] == None:
				if "optional" in Conf.confValues[i] and Conf.confValues[i]["optional"] == True:
					continue
				if "ask" in Conf.confValues[i] and Conf.confValues[i]["ask"] == True:
					while Conf.confValues[i]["value"] == None:
						sys.stdout.write("Please enter %s : " % Conf.confValues[i]["description"])
						val = sys.stdin.readline().strip()
						Conf.readConfFile(io.BytesIO("[CONFIGURATION]\n%s=%s" % (i, val)))
				else:
					raise Exception("Missing configuration option %s (%s)" % (i, Conf.confValues[i]["description"]))

	@staticmethod
	def getValue(key):
		return Conf.confValues[key]["value"]

	@staticmethod
	def getLabel(usage = None):
		if (usage == anssipki.USAGE_SIGNATURE) and (Conf.confValues["PKCS11_SIGNATURE_LABEL"]["value"] != None):
			return Conf.confValues["PKCS11_SIGNATURE_LABEL"]["value"]
		elif (usage == anssipki.USAGE_ENCRYPTION) and (Conf.confValues["PKCS11_ENCRYPTION_LABEL"]["value"] != None):
			return Conf.confValues["PKCS11_ENCRYPTION_LABEL"]["value"]
		else:
			return Conf.confValues["PKCS11_LABEL"]["value"]
