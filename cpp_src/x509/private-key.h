// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2013-2018 ANSSI. All Rights Reserved.
#ifndef PRIVATE_KEY_H_
# define PRIVATE_KEY_H_

# include <string>
# include <openssl/rsa.h>
# include <openssl/evp.h>

namespace LIBANSSIPKI
{

class RSAPrivateKey
{
public:

  /**
   *  @function RSAPrivateKey
   *  @brief    Création d'une clé privée
   */
  RSAPrivateKey(const std::string& _modulus,
		const std::string& _publicExponent,
		const std::string& _privateExponent,
		const std::string& _p,
		const std::string& _q,
		const std::string& _dmp1,
		const std::string& _dmq1,
		const std::string& _iqmp) {
    modulus = _modulus;
    publicExponent = _publicExponent;
    privateExponent = _privateExponent;
    p = _p;
    q = _q;
    dmp1 = _dmp1;
    dmq1 = _dmq1;
    iqmp = _iqmp;
  };

  std::string modulus;
  std::string publicExponent;
  std::string privateExponent;
  std::string p;
  std::string q;
  std::string dmp1;
  std::string dmq1;
  std::string iqmp;
};
} // namespace LIBANSSIPKI

#endif /* !PRIVATE_KEY_H_ */
