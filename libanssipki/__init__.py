# -*- coding: utf-8 -*-
# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright © 2013-2018 ANSSI. All Rights Reserved.

import gettext, sys, os

domain = 'libanssipki'
gettext.bindtextdomain(domain, sys.prefix + '/share/anssipki/locales/')

_ = lambda x : gettext.dgettext(domain, x)
