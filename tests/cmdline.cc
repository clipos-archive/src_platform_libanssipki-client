// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2013-2018 ANSSI. All Rights Reserved.
#include "csr.h"
#include "ca-certificate.h"
#include "db-helper.h"
#include "p11-helper.h"
#include "csr-template.h"
#include <unistd.h>
#include <iostream>
#include <getopt.h>
#include <string>
#include <cstdlib>

using namespace std;

#define NO_ARG 0
#define REQ_ARG 1
#define OPT_ARG 2

/* Commandes d'information */
#define ARG_HELP 10
#define ARG_VERSION 11

/* Commandes d'action AC */
#define ARG_CREATECA 20
#define ARG_LISTCA 21
#define ARG_DELETECA 22
#define ARG_EXPORTCA 23
#define ARG_IMPORTCA 24
#define ARG_GETCACERT 25
#define ARG_CREATESUBCA 26

/* Commandes d'action certificat final */
#define ARG_CREATECERT 30
#define ARG_LISTCERTS 31
#define ARG_LISTEXPIRED 32
#define ARG_IMPORTCSR 33
#define ARG_IMPORTCERT 34
#define ARG_EXPORTCERT 35
#define ARG_EXPORTCHAIN 36
#define ARG_RENEWCERT 37
#define ARG_CREATESELFSIGNCERT 38

/* Commandes d'action CRL */
#define ARG_CREATECRL 40
#define ARG_LISTCRL 41
#define ARG_LASTCRL 42
#define ARG_REVOKECERT 43
#define ARG_EXPORTCRL 44


/* Attributs d'un certificat */
#define ATT_CANAME 60
#define ATT_DN 61
#define ATT_VALIDITY 62
/* 63 reservé pour '?' */
#define ATT_VALIDFROM 64
#define ATT_VALIDUNTIL 65
#define ATT_SAN 66
#define ATT_TEMPLATE 67
#define ATT_KEYSIZE 68
#define ATT_KEYALGO 69
#define ATT_SIGNALGO 70


/* Attributs d'un fichier */
#define ATT_FILENAME 80
#define ATT_FORMAT 81
#define ATT_PASSWORD 82

/* Attributs d'une CRL */
#define ATT_NEXTUPDATE 90
#define ATT_DELTA 91
#define ATT_REASON 92
#define ATT_NUMBER 93

/* Autres attributs */
#define ATT_DAYS 100


void usage() {
    string s =
            "ANSSIPKI v1.0 Angelus \n\
Examples :\n\
Create a new CA \n\
\t anssipki --createca --caname AC1 --dn C=FR,O=SDE,CN=AC1 --template ROOT_CA \n\
Create a new certificate \n\
\t anssipki --createcert --caname AC1 --dn C=FR,O=DAT,CN=Petrus --template CLIENT_AUTH \n\
\t anssipki --createcert --caname AC1 --dn C=FR,O=DAT,CN=Server1 --san server1.gouv.fr --template SSL_SERVER \n\
List CA \n\
\t anssipki --listca \n\
List certificates \n\
\t anssipki --listcerts -caname AC1 \n\
Export certificate \n\
\t anssipki --exportcert --caname AC1 --dn C=FR,O=DAT,CN=Server1 --format pem --filename server1.pem --password 3#Avajp56k\n\
\n";
	cout << s;
}

int parse_arguments(int argc, char* argv[]) {
	int opterr = 0, action = 0;
	
	string cert_template="[template]\n";
	
    const struct option long_options[] =
    {
		/* Commandes d'information */
		{"help", OPT_ARG, 0, ARG_HELP},
        {"version", NO_ARG, 0, ARG_VERSION},
        
        /* Commandes d'action AC */
        {"createca", NO_ARG, 0, ARG_CREATECA},
        {"listca", NO_ARG, 0, ARG_LISTCA},
		{"deletca", NO_ARG, 0, ARG_DELETECA},
		{"exportca", NO_ARG, 0, ARG_EXPORTCA},
		{"importca", NO_ARG, 0,  ARG_IMPORTCA},
		{"getcacert", NO_ARG, 0, ARG_GETCACERT},
		{"createsubca", NO_ARG, 0, ARG_CREATESUBCA},        

		/* Commandes d'action certificat final */
		{"createcert", NO_ARG, 0, ARG_CREATECERT},
		{"listcerts", NO_ARG, 0, ARG_LISTCERTS},
		{"listexpired", NO_ARG, 0, ARG_LISTEXPIRED},
		{"importcsr", NO_ARG, 0, ARG_IMPORTCSR},
		{"importcert", NO_ARG, 0, ARG_IMPORTCERT},
		{"exportcert", NO_ARG, 0, ARG_EXPORTCERT},
		{"exportchain", NO_ARG, 0, ARG_EXPORTCHAIN},
		{"renewcert", NO_ARG, 0, ARG_RENEWCERT},
		{"create-selfsigned-cert", NO_ARG, 0, ARG_CREATESELFSIGNCERT},

		/* Commandes d'action CRL */
		{"createcrl", NO_ARG, 0, ARG_CREATECRL},
		{"listcrl", NO_ARG, 0, ARG_LISTCRL},
		{"lastcrl", NO_ARG, 0, ARG_LASTCRL},
		{"revokecert", NO_ARG, 0, ARG_REVOKECERT},
		{"exportcrl", NO_ARG, 0, ARG_EXPORTCRL},


		/* Attributs d'un certificat */
		//FIXME OPT_CREATE_CA_START + 0 1 2   OPT_CREATE_CA_END = 50
		{"caname", REQ_ARG, 0, ATT_CANAME},
		{"dn", REQ_ARG, 0, ATT_DN},
		{"validity", REQ_ARG, 0, ATT_VALIDITY},
		{"validfrom", REQ_ARG, 0, ATT_VALIDFROM},
		{"validuntil", REQ_ARG, 0, ATT_VALIDUNTIL},
		{"san", REQ_ARG, 0, ATT_SAN},
		{"template", REQ_ARG, 0, ATT_TEMPLATE},
		{"keysize", REQ_ARG, 0, ATT_KEYSIZE},
		{"keyalgo", REQ_ARG, 0, ATT_KEYALGO},
		{"signalgo", REQ_ARG, 0, ATT_SIGNALGO},


		/* Attributs d'un fichier */
		{"filename", REQ_ARG, 0, ATT_FILENAME},
		{"format", REQ_ARG, 0, ATT_FORMAT},
		{"password", REQ_ARG, 0, ATT_PASSWORD},

		/* Attributs d'une CRL */
		{"nextupdate", REQ_ARG, 0, ATT_NEXTUPDATE},
		{"delta", REQ_ARG, 0, ATT_DELTA},
		{"reason", REQ_ARG, 0, ATT_REASON},
		{"number", REQ_ARG, 0, ATT_NUMBER},

		/* Autres attributs */
		{"days", REQ_ARG, 0, ATT_DAYS}
    };
    
    while (1) {
		int option_index = 0, arg = 0;
		int cmd = getopt_long(argc, argv, "", long_options, &option_index);
		if (cmd == -1) break;
		
		/* Si une action est déjà spécifié, il faut rentrer dans le switch de 2e niveau */
		if (action != 0) {
			arg = cmd;
			cmd = action;
		}
		switch (cmd) {
			case ARG_HELP:
				usage();
				break;
			case ARG_VERSION:
				cout << "ANSSI-PKI v1.0 Angelus" << endl;
				break;
				
			/* Création de certificats */
			case ARG_CREATECA:
			case ARG_CREATESUBCA:
			case ARG_CREATESELFSIGNCERT:
			case ARG_CREATECERT:
				action = cmd;
				
				if (!arg) break;
				
				switch (arg) {
					case ATT_CANAME:
						break;
					case ATT_DN:
						cert_template += "dn=";
						cert_template += optarg;
						cert_template += "\n";
						break;
						// FIXME : gérer les 'now' et les périodes de validité (3y,2m,1d...)
					case ATT_VALIDITY:
						cert_template += "validityFrom=now\n";
						cert_template += "validityTo=";
						cert_template += optarg;
						cert_template += "\n";
						break;
					case ATT_VALIDFROM:
						cert_template += "validityFrom=";
						cert_template += optarg;
						cert_template += "\n";
						break;
					case ATT_VALIDUNTIL:
						cert_template += "validityTo=";
						cert_template += optarg;
						cert_template += "\n";
						break;
					case ATT_SAN:
						break;
					case ATT_TEMPLATE:
						break;
					case ATT_KEYSIZE:
						cert_template += "publicKeySize=";
						cert_template += optarg;
						cert_template += "\n";
						break;
					case ATT_KEYALGO:
						cert_template += "publicKeyAlgo=";
						cert_template += optarg;
						cert_template += "\n";
						break;
					case ATT_SIGNALGO:
						cert_template += "signAlgo=";
						cert_template += optarg;
						cert_template += "\n";
						break;
					default:
						cout << "Argument inconnu : " << argv[optind-1] << endl;
						//usage();
				}
				//cout << cert_template << endl;
				break;
			case 0:
				break;
			case '?':
				cout << "Commande inconnue : " << argv[optind-1] << endl;
				//usage();
				break;
			default:
				cout << "Argument inconnu : " << argv[optind-1] << endl;
				//usage();
		}
	}
	
	/* Executer la commande */
	/* FIXME : faire mieux que ce 2e switch */
	if (action) {
		CSRTemplate t;
		switch (action) {
			case ARG_CREATECA:
				cert_template += "issuerDN=SELF\n";
				cert_template += "keyUsage=CA\n";
				if (t.loadFromData(cert_template.c_str())) {
					t.generate();
				}
				else {
					// FIXME gestion erreur
					cout << "Erreur à la génération" << endl;
				}
				break;
			case ARG_CREATESUBCA:
				cert_template += "keyUsage=CA\n";
				if (t.loadFromData(cert_template.c_str())) {
					t.generate();
				}
				else {
					// FIXME gestion erreur
					cout << "Erreur à la génération" << endl;
				}
				break;
			default:
				cout << "Défaillance générale" << endl;
		}
	}
}


int main(int argc, char* argv[])
{
        P11Helper::initInstance("/mnt/dev/locale/lib/softhsm/libsofthsm.so",
		CKU_USER, "4242", "test");
		DBHelper::open("./libanssipki_client.db");
        parse_arguments(argc, argv);
        P11Helper::closeInstance();
		DBHelper::close();
        return EXIT_SUCCESS;
}
