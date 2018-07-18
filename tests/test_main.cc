// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2013-2018 ANSSI. All Rights Reserved.
#include "csr.h"
#include "ca-certificate.h"
#include "db-helper.h"
#include "p11-helper.h"
#include <unistd.h>
#include <iostream>

int main(void)
{
	P11Helper::initInstance("/usr/lib/softhsm/libsofthsm.so",
		CKU_USER, "4242", "test");
	DBHelper::open("./libanssipki_client.db");

	X509Name caDn;
	caDn.addField("c","FR");
	caDn.addField("st","France");
	caDn.addField("l","Paris");
	caDn.addField("o","FOO_O");
	caDn.addField("ou","FOO_OU");
	caDn.addField("cn","FOO_CN");

	CSR* csr = new CSR(caDn, true);
	csr->setKeyUsage(KU_CA);
	CACertificate* cacert = dynamic_cast<CACertificate*>(csr->selfSign("2012-10-10", "2014-10-10", S_ALGO_SHA256RSA));
	delete csr;

	X509Name certDn;
	certDn.addField("c","FR");
	certDn.addField("st","France");
	certDn.addField("l","Paris");
	certDn.addField("o","ANSSI");
	certDn.addField("ou","SDE");
	certDn.addField("cn","clip.ssi.gouv.fr");

	csr = new CSR(certDn, false);
	csr->setKeyUsage(KU_SSL_SERVER);
	csr->setExtendedKeyUsage(extendedKeyUsages[EKU_SERVERAUTH]);
	Certificate *cert = cacert->signCSR(*csr,"2012-10-10", "2014-10-10", S_ALGO_SHA256RSA);
	delete csr;

	delete cert;
	delete cacert;

	P11Helper::closeInstance();
	DBHelper::close();
}
