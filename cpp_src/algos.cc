// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2013-2018 ANSSI. All Rights Reserved.
#include <stdexcept>
#include <string.h>

#include "algos.h"

#include "pkcs11/p11-helper.h"
#include "utils.h"

namespace LIBANSSIPKI
{

static const s_sign_algo_table signAlgos[] =
{
  {"SHA1RSA", NID_sha1WithRSAEncryption, CKM_SHA1_RSA_PKCS},
  {"SHA256RSA", NID_sha256WithRSAEncryption, CKM_SHA256_RSA_PKCS},
  {"SHA512RSA", NID_sha512WithRSAEncryption, CKM_SHA512_RSA_PKCS},
};

const char*
SignAlgoP11MechToString(CK_MECHANISM_TYPE p11_mechanism) {
  for (unsigned int i = 0;
    i < sizeof(signAlgos) / sizeof(s_sign_algo_table);
    i++) {
    if (signAlgos[i].p11_mechanism == p11_mechanism)
      return signAlgos[i].str;
  }

  return 0;
}

unsigned long
SignAlgoP11MechToNID(CK_MECHANISM_TYPE p11_mechanism) {
  for (unsigned int i = 0;
    i < sizeof(signAlgos) / sizeof(s_sign_algo_table);
    i++) {
    if (signAlgos[i].p11_mechanism == p11_mechanism)
      return signAlgos[i].NID;
  }
  return 0;
}

CK_MECHANISM_TYPE
SignAlgoStrToP11Mech(const char *str) {
  for (unsigned int i = 0;
    i < sizeof(signAlgos) / sizeof(s_sign_algo_table);
    i++) {
    if (! strcmp(str, signAlgos[i].str))
      return signAlgos[i].p11_mechanism;
  }
  return 0;
}

unsigned long
SignAlgoStrToNID(const char *str) {
  for (unsigned int i = 0;
    i < sizeof(signAlgos) / sizeof(s_sign_algo_table);
    i++) {
    if (! strcmp(str, signAlgos[i].str))
      return signAlgos[i].NID;
  }
  return 0;
}

const char*
SignAlgoNIDToStr(unsigned long NID) {
  for (unsigned int i = 0;
    i < sizeof(signAlgos) / sizeof(s_sign_algo_table);
    i++) {
    if (signAlgos[i].NID == NID)
      return signAlgos[i].str;
  }
  return 0;
}

CK_MECHANISM_TYPE
SignAlgoNIDToP11Mech(unsigned long NID) {
  for (unsigned int i = 0;
    i < sizeof(signAlgos) / sizeof(s_sign_algo_table);
    i++) {
    if (signAlgos[i].NID == NID)
      return signAlgos[i].p11_mechanism;
  }
  return 0;
}


key_pair_algo_e keyPairAlgoFromStr(const std::string& str) {
  if (str == "RSA")
    return KPA_RSA;
  throw std::invalid_argument("Invalid keyPair string");
}

}
