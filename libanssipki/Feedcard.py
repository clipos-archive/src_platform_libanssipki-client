# -*- coding: utf-8 -*-
# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright © 2013-2018 ANSSI. All Rights Reserved.

import anssipki
from Conf import Conf

def feedCard(cert):
    p11SC = anssipki.P11Helper.connect(Conf.getValue("PKCS11_SMARTCARD_MODULE"),
				       Conf.getValue("PKCS11_SMARTCARD_PIN"),
				       Conf.getValue("PKCS11_SMARTCARD_LABEL"),
				       Conf.getValue("PKCS11_SMARTCARD_SLOT") != None,
				       Conf.getValue("PKCS11_SMARTCARD_SLOT"))
    p11SoftHSM =  anssipki.P11Helper.getInstance()
    cert.fetchP11PrivateKeyHandle()
    cert.fetchX509Cert()
    privKey = p11SoftHSM.extractRSAPrivateKey(cert.hPrivateKey)
    label = Conf.getLabel(anssipki.USAGE_ENCRYPTION)
    p11SC.writeRSAPrivateKey(privKey,
			     cert.cryptoID,
			     True,
			     label,
			     anssipki.USAGE_ENCRYPTION)
    p11SC.writeCertificate(cert.x509, cert.cryptoID, label)
