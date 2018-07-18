// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2013-2018 ANSSI. All Rights Reserved.
#include <assert.h>
#include "csr.h"
#include "ca-certificate.h"
#include "p11-helper.h"
#include "db-helper.h"
#include <unistd.h>
#include <iostream>

int main(void)
{
	P11Helper::initInstance("/usr/lib/softhsm/libsofthsm.so",
		CKU_USER, "4242", "test");
	DBHelper::open("./libanssipki_client.db");

	// P11Helper::initInstance("/mnt/dev/locale/lib/softhsm/libsofthsm.so",
	// 	CKU_USER, "4242", "test");

	X509Name* dn;
	CSR* csr;
	CACertificate* ca_root;
	CACertificate* ca_servers;
	CACertificate* ca_clients;
	Certificate* https_serv;
	Certificate* https_client_1;
	Certificate* https_client_2;

	dn = new X509Name();
	dn->addField("c","FR");
	dn->addField("st","France");
	dn->addField("l","Paris");
	dn->addField("o","FOO_O");
	dn->addField("ou","FOO_OU");
	dn->addField("cn","FOO_CN_ROOT");
	csr = new CSR(*dn, true);
	csr->setKeyUsage(KU_CA);
	ca_root = dynamic_cast<CACertificate*>(csr->selfSign("2012-10-10", "2014-10-10", S_ALGO_SHA256RSA));
	assert(ca_root != 0);
	delete dn;
	delete csr;

	dn = new X509Name();
	dn->addField("c","FR");
	dn->addField("st","France");
	dn->addField("l","Paris");
	dn->addField("o","FOO_O");
	dn->addField("ou","FOO_OU");
	dn->addField("cn","FOO_CN_SERVERS");
	csr = new CSR(*dn, true);
	csr->setKeyUsage(KU_CA);
	ca_servers = dynamic_cast<CACertificate*>(ca_root->signCSR(*csr,"2012-10-10", "2014-10-10", S_ALGO_SHA256RSA));
	assert(ca_servers != 0);
	delete dn;
	delete csr;


	dn = new X509Name();
	dn->addField("c","FR");
	dn->addField("st","France");
	dn->addField("l","Paris");
	dn->addField("o","FOO_O");
	dn->addField("ou","FOO_OU");
	dn->addField("cn","FOO_CN_CLIENTS");
	csr = new CSR(*dn, true);
	csr->setKeyUsage(KU_CA);
	ca_clients = dynamic_cast<CACertificate*>(ca_root->signCSR(*csr,"2012-10-10", "2014-10-10", S_ALGO_SHA256RSA));
	delete dn;
	delete csr;


	dn = new X509Name();
	dn->addField("c","FR");
	dn->addField("st","France");
	dn->addField("l","Paris");
	dn->addField("o","ANSSI");
	dn->addField("ou","SDE");
	dn->addField("cn","clip.ssi.gouv.fr");
	csr = new CSR(*dn, false);
	csr->setKeyUsage(KU_SSL_SERVER);
	csr->setExtendedKeyUsage(extendedKeyUsages[EKU_SERVERAUTH]);
	csr->addSubjectAltNameDNS("clip.ssi.gouv.fr");
	https_serv = ca_servers->signCSR(*csr,"2012-10-10", "2014-10-10", S_ALGO_SHA256RSA);
	delete dn;
	delete csr;

	dn = new X509Name();
	dn->addField("c","FR");
	dn->addField("st","France");
	dn->addField("l","Paris");
	dn->addField("o","ANSSI");
	dn->addField("ou","SDE");
	dn->addField("cn","bob.demo");
	csr = new CSR(*dn, false);
	csr->setKeyUsage(KU_SSL_CLIENT);
	csr->setExtendedKeyUsage(extendedKeyUsages[EKU_CLIENTAUTH]);
	https_client_1 = ca_clients->signCSR(*csr,"2012-10-10", "2014-10-10", S_ALGO_SHA256RSA);
	delete dn;
	delete csr;

	dn = new X509Name();
	dn->addField("c","FR");
	dn->addField("st","France");
	dn->addField("l","Paris");
	dn->addField("o","ANSSI");
	dn->addField("ou","SDE");
	dn->addField("cn","alice.demo");
	csr = new CSR(*dn, false);
	csr->setKeyUsage(KU_SSL_CLIENT);
	csr->setExtendedKeyUsage(extendedKeyUsages[EKU_CLIENTAUTH]);
	https_client_2 = ca_clients->signCSR(*csr,"2012-10-10", "2014-10-10", S_ALGO_SHA256RSA);
	delete dn;
	delete csr;

	DBHelper::getInstance()->save(*ca_root);
	DBHelper::getInstance()->save(*ca_servers);
	DBHelper::getInstance()->save(*ca_clients);
	DBHelper::getInstance()->save(*https_serv);
	DBHelper::getInstance()->save(*https_client_1);
	DBHelper::getInstance()->save(*https_client_2);


	delete ca_root;
	delete ca_servers;
	delete ca_clients;
	delete https_serv;
	delete https_client_1;
	delete https_client_2;


	P11Helper::closeInstance();
	DBHelper::close();
}
