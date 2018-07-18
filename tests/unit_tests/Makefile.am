# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright © 2013-2018 ANSSI. All Rights Reserved.
TESTS=check_x509name
check_PROGRAMS = check_x509name
check_x509name_SOURCES = check_x509name.cc
check_x509name_CXXFLAGS = @CXXFLAGS@ @CHECK_CFLAGS@ -I$(VPATH)/$(top_builddir)/src
check_x509name_LDADD = $(top_builddir)/src/libanssipki-client.la @CHECK_LIBS@  @LDFLAGS@ -lanssipki-crypto






