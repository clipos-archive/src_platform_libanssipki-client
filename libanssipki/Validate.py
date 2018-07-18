# -*- coding: utf-8 -*-
# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright © 2013-2018 ANSSI. All Rights Reserved.

from Conf import Conf
from subprocess import Popen, PIPE
import sys
from tempfile import mkstemp
from os import remove, write, close

def ValidateTBS(x509_check_path, tbsDER, issuerDER=None):
	if issuerDER !=None:
		tmpFileFp, tmpFilePath = mkstemp()
		write(tmpFileFp, issuerDER)
		close(tmpFileFp)
		p = Popen([x509_check_path, '--issuer', tmpFilePath], stderr=PIPE, stdin=PIPE, stdout=PIPE)
		stdout, stderr = p.communicate(tbsDER)
		remove(tmpFilePath)
	else:
		p = Popen([x509_check_path], stderr=PIPE, stdin=PIPE, stdout=PIPE)
		stdout, stderr = p.communicate(tbsDER)
	sys.stderr.write(stderr)
	return p.returncode == 0
