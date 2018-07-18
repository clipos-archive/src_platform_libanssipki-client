# -*- coding: utf-8 -*-
# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright © 2013-2018 ANSSI. All Rights Reserved.

import os, sys, io
import ConfigParser
from libanssipki import _
from libanssipki.Conf import Conf

def parseTemplate(name, template = None):

    template_filepath = None

    for template_dir in Conf.getValue("TEMPLATES_DIR"):
      if not template_dir.endswith("/"):
        template_dir = template_dir + "/"
      if os.path.exists(template_dir + name + ".tpl"):
        template_filepath = template_dir + name + ".tpl"
    if not template_filepath:
      raise Exception (_("TEMPLATE_NOT_FOUND") % (name, (" (" + template['source'] + ")") if template else ""))

    templateConf = ConfigParser.ConfigParser()
    with open(template_filepath, "r") as fp:
      templateConf.readfp(fp)

    if not template:
      template = {}
      template['source']=template_filepath
      template['values']={}

    if 'CERTIFICATE' not in templateConf.sections():
      raise Exception (_("TEMPLATE_NO_CERTIFICATE_SECTION") % template_filepath)
    if 'PARENT' in templateConf.sections():
      for (i,v) in templateConf.items('PARENT'):
        if i != 'template':
          raise Exception (_("TEMPLATE_PARENT_SECTION_INVALID_KEY") % template_filepath)
        if 'parent' in template:
          raise Exception (_("TEMPLATE_MULTIPLE_PARENT") % template_filepath)
        else:
          template = parseTemplate(v, template)

    for (i,v) in templateConf.items('CERTIFICATE'):
      template['values'][i] = v

    return template
