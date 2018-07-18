// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2013-2018 ANSSI. All Rights Reserved.
#ifndef PUBLIC_KEY_H_
# define PUBLIC_KEY_H_

# include <string>
# include <openssl/rsa.h>
# include <openssl/evp.h>

namespace LIBANSSIPKI
{
/**
 *  key_pair_algo_e liste les différents types de bi-clé pouvant être utilisés.
 *  actuellement, seuls les bi-clé RSA sont possibles.
 */
enum key_pair_algo_e {
  KPA_RSA,
  // KPA_EC  // Not Implemented yet
};

/**
 * @class PublicKey
 * @brief Classe representant une clé publique.
 *        Utilise un objet OpenSSL EVP_PKEY
 */
class PublicKey
{
public:
  virtual ~PublicKey() {};
  EVP_PKEY*  pkey;
};

class RSAPublicKey : public PublicKey
{
public:

  /**
   *  @function RSAPublicKey
   *  @brief    Création d'une clé publique
   */
  RSAPublicKey(const std::string& modulus,
         const std::string& publicExponent) {
      rsa = RSA_new ();
      rsa->n = BN_bin2bn((const unsigned char*)(modulus.c_str()), modulus.size(), NULL);
      rsa->e = BN_bin2bn((const unsigned char*)(publicExponent.c_str()), publicExponent.size(), NULL);
      pkey = EVP_PKEY_new();
      EVP_PKEY_assign_RSA(pkey,  rsa);
    };

  virtual ~RSAPublicKey() {
    RSA_free(EVP_PKEY_get1_RSA(pkey)); EVP_PKEY_free(pkey);}
public:
  RSA*  rsa;
};
} // namespace LIBANSSIPKI

#endif /* !PUBLIC_KEY_H_ */
