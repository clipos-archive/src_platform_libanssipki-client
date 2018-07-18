# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright © 2013-2018 ANSSI. All Rights Reserved.
lib_LTLIBRARIES = libanssipki-client.la

libanssipki_client_la_SOURCES = \
	pkcs11/libscdl.c		\
	pkcs11/libpkcs11.c		\
	pkcs11/p11-helper.cc	\
	pkcs11/p11-exception.cc \
	x509/x509req.cc			\
	x509/x509cert.cc		\
	x509/x509name.cc		\
	p12_export.cc			\
	csr_export.cc			\
	algos.cc				\
	utils.cc

libanssipki_client_la_LDFLAGS = -version-info @VERSION_INFO@

pkcs11includedir = $(includedir)/pkcs11
pkcs11include_HEADERS = \
	pkcs11/libpkcs11.h		\
	pkcs11/libscdl.h		\
	pkcs11/pkcs11.h			\
	pkcs11/p11-helper.h		\
	pkcs11/p11-exception.h

x509includedir = $(includedir)/x509
x509include_HEADERS = \
	x509/x509req.h			\
	x509/x509cert.h			\
	x509/x509name.h			\
	x509/public-key.h


include_HEADERS =			\
	utils.h
