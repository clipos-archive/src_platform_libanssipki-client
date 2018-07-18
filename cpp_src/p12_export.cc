// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2013-2018 ANSSI. All Rights Reserved.
#include <stdexcept>
#include <openssl/pkcs12.h>

#include "pkcs11/pkcs11.h"

#include "p12_export.h"
#include "pkcs11/p11-helper.h"
#include "utils.h"

static std::string wrapIVStr = "";
static CK_BBOOL _true = TRUE;

namespace LIBANSSIPKI {


void
PKCS12_INIT_WITH_PROXY(const CK_OBJECT_HANDLE  hKeyToWrap,
            CK_OBJECT_HANDLE*       wrapKeyHandle,
            CK_OBJECT_HANDLE*       hmacKeyHandle,
            unsigned long*          iter,
            std::string&            salt,
            const std::string&      password)
{
  CK_RV      rv;
  CK_BYTE      buffOut[5000];
  CK_ULONG    buffOutLen = 5000;
  unsigned long  vendorDefinedMechanism;
  unsigned long long	tmp = 0;

  // NID_pbe_WithSHA1And3_Key_TripleDES_CBC:
  vendorDefinedMechanism = -1UL;

  // Le mot de passe est jeté
  (void)password;

  // Private Key Wrapping
  CK_MECHANISM  ck_mech = { vendorDefinedMechanism, NULL, 0 };

  rv = P11Helper::getInstance()->p11->C_WrapKey(
       P11Helper::getInstance()->hSession, &ck_mech,
                              0, hKeyToWrap, buffOut, &buffOutLen);

  if (rv != CKR_OK)
    throw P11Exception(rv, "C_WrapKey");

  unsigned long long saltLen = 0;
  for (int i = 0; i < 8; ++i)
    ((char*)&tmp)[i] = (buffOut[7 - i]);
  *wrapKeyHandle = tmp;
  for (int i = 0; i < 8; ++i)
    ((char*)&tmp)[i] = (buffOut[15 - i]);
  *hmacKeyHandle = tmp;
  for (int i = 0; i < 8; ++i)
    ((char*)&tmp)[i] = (buffOut[23 - i]);
  *iter = tmp;
  for (int i = 0; i < 8; ++i)
    ((char*)&saltLen)[i] = (buffOut[31 - i]);
  salt = std::string ((char*)(buffOut + 32), 0, saltLen);
}

void
PKCS12_INIT_WITHOUT_PROXY(const CK_OBJECT_HANDLE hKeyToWrap,
            CK_OBJECT_HANDLE*      wrapKeyHandle,
            CK_OBJECT_HANDLE*      hmacKeyHandle,
            unsigned long*         iter,
            std::string&           salt,
            const std::string&     password)
{
  unsigned int  saltLen = 0;

  unsigned int  wrapKeyLen = 0;
  unsigned char*  wrapKeyOut;
  CK_OBJECT_CLASS wrap_keyClass = CKO_SECRET_KEY;
  CK_KEY_TYPE    wrap_keyType;

  unsigned int  wrapIVLen = 0;

  unsigned int  hmacKeyLen = 0;
  unsigned char*  hmackeyOut;
  CK_OBJECT_CLASS hmac_keyClass = CKO_SECRET_KEY;
  CK_KEY_TYPE    hmac_keyType;

  const EVP_MD*      md_type;

  *iter = 2048;

  // NID_pbe_WithSHA1And3_Key_TripleDES_CBC;
  wrapKeyLen = 24;
  wrap_keyType = CKK_DES3;
  wrapIVLen = 8;
  saltLen = 8;
  hmacKeyLen = 20;
  hmac_keyType = CKK_SHA_1_HMAC;
  md_type = EVP_get_digestbynid(NID_sha1);

  salt.resize(saltLen);
  P11Helper::getInstance()->generateRandom((unsigned char*)salt.c_str(), saltLen);

  wrapKeyOut = new unsigned char[wrapKeyLen];
  if (!PKCS12_key_gen (password.c_str(), password.length(),
             (unsigned char*)salt.c_str(), saltLen, PKCS12_KEY_ID,
             *iter, wrapKeyLen, wrapKeyOut,
             md_type))
    throw std::logic_error("Certificate::extractToP12 : PKCS12_key_gen Failure");
  CK_ATTRIBUTE  wrap_keyTemplate[] = {
    {CKA_CLASS, &wrap_keyClass, sizeof(wrap_keyClass)},
    {CKA_KEY_TYPE, &wrap_keyType, sizeof(wrap_keyType)},
    {CKA_WRAP, &_true, sizeof(_true)},
    {CKA_VALUE, (void*)(wrapKeyOut), wrapKeyLen},
  };

  P11Helper::getInstance()->createObject(wrap_keyTemplate, 4, wrapKeyHandle);
  delete wrapKeyOut;

  wrapIVStr.resize(wrapIVLen);
  if (!PKCS12_key_gen (password.c_str(), password.length(),
             (unsigned char*)salt.c_str(), saltLen, PKCS12_IV_ID,
             *iter, wrapIVLen, (unsigned char*)wrapIVStr.c_str(),
             md_type))
    throw std::logic_error("Certificate::extractToP12 : PKCS12_key_gen Failure");

  hmackeyOut = new unsigned char[hmacKeyLen];
  if (!PKCS12_key_gen (password.c_str(), password.length(),
             (unsigned char*)salt.c_str(), saltLen, PKCS12_MAC_ID,
             *iter, hmacKeyLen, hmackeyOut,
             md_type))
    throw std::logic_error("Certificate::extractToP12 : PKCS12_key_gen Failure");
  CK_ATTRIBUTE  hmac_keyTemplate[] = {
    {CKA_CLASS, &hmac_keyClass, sizeof(hmac_keyClass)},
    {CKA_KEY_TYPE, &hmac_keyType, sizeof(hmac_keyType)},
    {CKA_SIGN, &_true, sizeof(_true)},
    {CKA_VALUE, (void*)(hmackeyOut), hmacKeyLen},
  };
  P11Helper::getInstance()->createObject(hmac_keyTemplate, 4, hmacKeyHandle);
  delete hmackeyOut;
}



void PKCS12_INIT(const CK_OBJECT_HANDLE  hKeyToWrap,
                CK_OBJECT_HANDLE*       wrapKeyHandle,
                CK_OBJECT_HANDLE*       hmacKeyHandle,
                unsigned long*          iter,
                std::string&            salt,
                const std::string&      password,
                const bool              withProxy)
{
  if (withProxy)
    PKCS12_INIT_WITH_PROXY(hKeyToWrap, wrapKeyHandle, hmacKeyHandle,
                           iter, salt, password);
  else
    PKCS12_INIT_WITHOUT_PROXY(hKeyToWrap, wrapKeyHandle, hmacKeyHandle,
                              iter, salt, password);
}


static PKCS12_SAFEBAG*
createCertificateSafeBag(std::string derContent) {
  PKCS12_BAGS          *p12bag = NULL;
  PKCS12_SAFEBAG        *p12safeBag = NULL;

  if (!(p12bag = PKCS12_BAGS_new()))
    throw std::bad_alloc();
  p12bag->type = OBJ_nid2obj(NID_x509Certificate);
  if (!(p12bag->value.octet = M_ASN1_OCTET_STRING_new()))
    throw std::bad_alloc();
  M_ASN1_OCTET_STRING_set(p12bag->value.octet, derContent.c_str(), derContent.length());
  /* FIXME Chain : Set bag info */
  // if(name && !PKCS12_add_friendlyname(bag, name, -1))
  //   goto err;
  // if(keyidlen && !PKCS12_add_localkeyid(bag, keyid, keyidlen))
  //   goto err;
  // Ajout du bag de certificat dans un safebag
  if (!(p12safeBag = PKCS12_SAFEBAG_new()))
    throw std::bad_alloc();
  p12safeBag->value.bag = p12bag;
  p12safeBag->type = OBJ_nid2obj(NID_certBag);

  return p12safeBag;
}

int PKCS12_gen_mac_(PKCS12*       p12,
          CK_OBJECT_HANDLE  hmacKeyHandle,
          std::string&    mac,
          const EVP_MD*    md_type)
{
  if (!PKCS7_type_is_data(p12->authsafes))
    throw std::logic_error("Certificate::PKCS12_gen_mac_ : PKCS12_F_PKCS12_GEN_MAC,PKCS12_R_CONTENT_TYPE_NOT_DATA");

  if(!(md_type = EVP_get_digestbyobj (p12->mac->dinfo->algor->algorithm)))
    throw std::logic_error("Certificate::PKCS12_gen_mac_ : PKCS12_F_PKCS12_GEN_MAC,PKCS12_R_UNKNOWN_DIGEST_ALGORITHM");

  mac = P11Helper::getInstance()->sign(std::string((char*)p12->authsafes->d.data->data, p12->authsafes->d.data->length),
                  CKM_SHA_1_HMAC, hmacKeyHandle);
  return 1;
}

int PKCS12_set_mac_(PKCS12*       p12,
          CK_OBJECT_HANDLE  hmacKeyHandle,
          const std::string&  salt,
          int          iter,
          const EVP_MD*    md_type)
{
  std::string   mac;

  if (!md_type) md_type = EVP_sha1();
  if (PKCS12_setup_mac (p12, iter, (unsigned char*)salt.c_str(), salt.length(), md_type) ==
          PKCS12_ERROR)
    throw std::logic_error("Certificate::PKCS12_set_mac_ : PKCS12_F_PKCS12_SET_MAC,PKCS12_R_MAC_SETUP_ERROR");


  if (!PKCS12_gen_mac_ (p12, hmacKeyHandle, mac, md_type))
    throw std::logic_error("Certificate::PKCS12_set_mac_ : PKCS12_F_PKCS12_SET_MAC,PKCS12_R_MAC_GENERATION_ERROR");


  if (!(M_ASN1_OCTET_STRING_set (p12->mac->dinfo->digest, mac.c_str(), mac.length())))
    throw std::logic_error("Certificate::PKCS12_set_mac_ : PKCS12_F_PKCS12_SET_MAC,PKCS12_R_MAC_STRING_SET_ERROR");
  return 1;
}

std::string
extractToP12(unsigned long       hPrivateKey,
       std::string        certder,
       std::list<std::string>    chain,
       std::string        password,
       const bool         withProxy) {

  PKCS12            *p12 = NULL;
  PKCS12_SAFEBAG        *p12safeBag = NULL;
  STACK_OF(PKCS12_SAFEBAG)  *p12safeBags = NULL;
  PKCS7            *p7safe = NULL;
  STACK_OF(PKCS7)        *p7safes = NULL;
  std::string          derContent;
  X509*            x509cert;

  int          key_pbe = NID_pbe_WithSHA1And3_Key_TripleDES_CBC;
  unsigned char    keyid[EVP_MAX_MD_SIZE];
  unsigned int    keyidlen = 0;
  unsigned long    iter = 0;
  std::string      wrapSalt;
  CK_OBJECT_HANDLE  wrapKeyHandle;
  CK_OBJECT_HANDLE  hmacKeyHandle;

  // NID_pbe_WithSHA1And3_Key_TripleDES_CBC;
  PKCS12_INIT(hPrivateKey, &wrapKeyHandle, &hmacKeyHandle,
              &iter, wrapSalt, password, withProxy);

  if (!(p7safes = sk_PKCS7_new_null()))
    throw std::bad_alloc();
  if (!(p12safeBags = sk_PKCS12_SAFEBAG_new_null()))
    throw std::bad_alloc();

  // Creation de safebags pour le certificat exporté
  x509cert = DERtoX509(certder);
  p12safeBag = PKCS12_add_cert(&p12safeBags, x509cert);
  X509_digest(x509cert, EVP_sha1(), keyid, &keyidlen);
  X509_free(x509cert);
  PKCS12_add_localkeyid(p12safeBag, keyid, keyidlen);

  for (std::list<std::string>::const_iterator certIter = chain.begin();
    certIter != chain.end(); certIter++)
    sk_PKCS12_SAFEBAG_push(p12safeBags, createCertificateSafeBag(*certIter));

  // On pack les safebags dans conteneur PKCS7
  p7safe = PKCS7_new();
  p7safe->type = OBJ_nid2obj(NID_pkcs7_data);
  if (!(p7safe->d.data = M_ASN1_OCTET_STRING_new()))
    throw std::bad_alloc();
  if (!ASN1_item_pack(p12safeBags, ASN1_ITEM_rptr(PKCS12_SAFEBAGS), &(p7safe->d.data)))
    throw std::logic_error("Certificate::extractToP12 : ASN1_item_pack Failure");
  if (!sk_PKCS7_push(p7safes, p7safe))
    throw std::logic_error("Certificate::extractToP12 : sk_PKCS7_push Failure");

  // Une fois packé, on peut détruire les safebags
  sk_PKCS12_SAFEBAG_pop_free(p12safeBags, PKCS12_SAFEBAG_free);

  if (!(p12safeBags = sk_PKCS12_SAFEBAG_new_null()))
    throw std::bad_alloc();

  // Extraction de la clé privée wrappée
  std::string wrappedKey = P11Helper::getInstance()->
      wrap(hPrivateKey, wrapKeyHandle, CKM_DES3_CBC_PAD, wrapIVStr);

  // Création d'un safebag pour la clé wrappée
  if (!(p12safeBag = PKCS12_SAFEBAG_new()))
    throw std::bad_alloc();
  p12safeBag->type = OBJ_nid2obj(NID_pkcs8ShroudedKeyBag);
  // (Openssl) Utilisation de la structure X509_SIG pour créer un "PKCS8ShroudedKeyBad"
  if (!(p12safeBag->value.shkeybag = X509_SIG_new()))
    throw std::bad_alloc();

  if (!(p12safeBag->value.shkeybag->algor =
      PKCS5_pbe_set(key_pbe , iter,
        (const unsigned char*)wrapSalt.c_str(), wrapSalt.length())))
    throw std::logic_error("Certificate::extractToP12 : PKCS5_pbe2_set_iv Failure");

  p12safeBag->value.shkeybag->digest = M_ASN1_OCTET_STRING_new();
  M_ASN1_OCTET_STRING_set(p12safeBag->value.shkeybag->digest,
              wrappedKey.c_str(), wrappedKey.length());
  PKCS12_add_localkeyid(p12safeBag, keyid, keyidlen);

  sk_PKCS12_SAFEBAG_push(p12safeBags, p12safeBag);

  // On pack le safebag dans un conteneur PKCS7
  p7safe = PKCS7_new();
  p7safe->type = OBJ_nid2obj(NID_pkcs7_data);
  if (!(p7safe->d.data = M_ASN1_OCTET_STRING_new()))
    throw std::bad_alloc();
  if (!ASN1_item_pack(p12safeBags, ASN1_ITEM_rptr(PKCS12_SAFEBAGS), &(p7safe->d.data)))
    throw std::logic_error("Certificate::extractToP12 : ASN1_item_pack Failure");
  if (!sk_PKCS7_push(p7safes, p7safe))
    throw std::logic_error("Certificate::extractToP12 : sk_PKCS7_push Failure");

  // Une fois packé, on peut détruire les safebags
  sk_PKCS12_SAFEBAG_pop_free(p12safeBags, PKCS12_SAFEBAG_free);

  // Création du p12 à partir de la liste de conteneurs PKCS7
  if (!(p12 = PKCS12_add_safes(p7safes, 0)))
    throw std::logic_error("Certificate::extractToP12 : PKCS12_add_safes Failure");

  sk_PKCS7_pop_free(p7safes, PKCS7_free);

  if (!PKCS12_set_mac_(p12, hmacKeyHandle , wrapSalt, iter, EVP_sha1()))
    throw std::logic_error("Certificate::extractToP12 : PKCS12_set_mac Failure");

  BIO    *bio = NULL;
  bio = BIO_new(BIO_s_mem());
  i2d_PKCS12_bio(bio, p12);
  derContent = bio2string(bio);

  PKCS12_free(p12);

  return derContent;
}

}
