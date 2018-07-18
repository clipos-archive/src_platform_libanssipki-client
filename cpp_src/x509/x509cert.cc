// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2013-2018 ANSSI. All Rights Reserved.
#include <assert.h>
#include <stdexcept>

#include "x509cert.h"

using namespace LIBANSSIPKI;

X509Cert*
X509Cert::FromX509Tbs(X509Tbs*       tbs,
                      const std::string&  signature)
{
  X509Cert*  cert = dynamic_cast<X509Cert*>(tbs);
  cert->signature = signature;

  ASN1_BIT_STRING_set(cert->osslX509->signature,
    (unsigned char*)(signature.c_str()), signature.size());
  cert->osslX509->signature->flags &= ~(ASN1_STRING_FLAG_BITS_LEFT|0x07);
  cert->osslX509->signature->flags |= ASN1_STRING_FLAG_BITS_LEFT;

  BIO *bo = BIO_new(BIO_s_mem());
  i2d_X509_bio(bo, cert->osslX509);
  cert->derX509 = bio2string(bo);

  return cert;
}

X509Cert::X509Cert() :
  signature(""),
  derX509("")
{
}

X509Cert::~X509Cert()
{
}

X509Tbs*
X509Cert::renew(const std::string&  notBefore,
                const std::string&  notAfter)
{
  this->signature = "";
  this->derX509 = "";
  this->notBefore = notBefore;
  this->notAfter = notAfter;

  // validity period
  ASN1_UTCTIME_set_string(X509_get_notBefore(this->osslX509), notBefore.c_str());
  ASN1_UTCTIME_set_string(X509_get_notAfter(this->osslX509), notAfter.c_str());

  ASN1_BIT_STRING_set(this->osslX509->signature, NULL, 0);

  // create
  X509* x = X509_new();
  // set version to 3 (value 2)
  X509_set_version(x, 2);

  // public key
  X509_set_pubkey(x,  X509_get_pubkey(this->osslX509));

  // subject
  X509_set_subject_name(x, X509_get_subject_name(this->osslX509));

  // issuer
  X509_set_issuer_name(x, X509_get_issuer_name(this->osslX509));


  // serial
  X509_set_serialNumber(x, X509_get_serialNumber(this->osslX509));

  // validity period
  ASN1_UTCTIME_set_string(X509_get_notBefore(x), notBefore.c_str());
  ASN1_UTCTIME_set_string(X509_get_notAfter(x), notAfter.c_str());

  // extensions
  for (int i = 0; i < sk_X509_EXTENSION_num(this->osslX509->cert_info->extensions); i++)
    X509_add_ext(x, sk_X509_EXTENSION_value(this->osslX509->cert_info->extensions, i) , -1);

  // X509_ALGOR_set0(x->cert_info->signature, OBJ_nid2obj(NID_sha1WithRSAEncryption), V_ASN1_NULL, NULL);
  x->cert_info->signature = X509_ALGOR_dup(this->osslX509->cert_info->signature);
  x->sig_alg = X509_ALGOR_dup(this->osslX509->sig_alg);

  X509_free(this->osslX509);

  this->osslX509 = x;

  return dynamic_cast<X509Tbs*> (this);
}


static void get_basic_constraints(X509_EXTENSION *ex, bool *ca, unsigned int *pathlen)
{
  BASIC_CONSTRAINTS *bs = (BASIC_CONSTRAINTS *)X509V3_EXT_d2i(ex);
  assert(bs != 0);
  *ca = (bs->ca ? true: false);
  if(bs->pathlen)
    *pathlen = ASN1_INTEGER_get(bs->pathlen);
  else
    *pathlen = 0;
  BASIC_CONSTRAINTS_free(bs);
}

X509Cert*
X509Cert::fromDER(const std::string& DER)
{
  BIO*      bi = NULL;
  X509*       x = NULL;
  X509_EXTENSION*  ex = NULL;
  X509Cert*    cert = NULL;
  X509Name    subjectDN;
  X509Name    issuerDN;
  std::string    notBefore;
  std::string    notAfter;
  std::string    serialNumber;
  std::string    signature;

  bi = BIO_new(BIO_s_mem());
  BIO_write(bi, DER.c_str(), DER.size());
  x = d2i_X509_bio(bi, NULL);
  BIO_free(bi);

  if (!x)
    throw std::logic_error("X509Cert::fromDER : Error during der parsing.");

  // Check that the certificate version is 3 (value 2)
  if (X509_get_version(x) != 2)
    throw std::logic_error("X509Cert::fromDER : Only X509v3 expected.");

  subjectDN.fromOSSLX509_NAME(X509_get_subject_name(x));
  issuerDN.fromOSSLX509_NAME(X509_get_issuer_name(x));

  ASN1_INTEGER *ai = X509_get_serialNumber(x);
  if (ai)
    serialNumber = std::string((char*)ai->data,ai->length);

  assert (X509_get_notBefore(x)->type == V_ASN1_UTCTIME);
  assert (X509_get_notAfter(x)->type == V_ASN1_UTCTIME);

  notBefore = std::string((char*)(X509_get_notBefore(x)->data));
  notAfter = std::string((char*)(X509_get_notAfter(x)->data));

  if (x->signature)
  {
    signature = std::string(x->signature->length, 0);
    for (int i=0; i< x->signature->length; i++)
      signature[i] = x->signature->data[i];
  }

  cert = new X509Cert();
  cert->subjectDN = subjectDN.toString();
  cert->notBefore = notBefore;
  cert->notAfter = notAfter;
  cert->signAlgorithmNID = OBJ_obj2nid(x->cert_info->signature->algorithm);
  cert->serialNumber = serialNumber;
  cert->issuerDN = issuerDN;
  cert->signature = signature;

  int pos = X509_get_ext_by_NID(x, NID_basic_constraints, -1);
  if(pos != -1)
  {
    if ((ex = X509_get_ext(x, pos)) != NULL)
      get_basic_constraints(ex, &(cert->isCAFlag), &(cert->caPathLimit));
  }

  pos = X509_get_ext_by_NID(x, NID_subject_alt_name, -1);
  if(pos != -1)
  {
    if ((ex = X509_get_ext(x, pos)) != NULL)
      //FIXME TODO
      throw (0);
  }

  // pos = X509_get_ext_by_NID(x, NID_issuer_alt_name, -1);
  // if(pos != -1)
  // {
  //   if ((ex = X509_get_ext(x, pos)) != NULL)
  //     //FIXME TODO
  //     throw (0);
  // }

  pos = X509_get_ext_by_NID(x, NID_key_usage, -1);
  if(pos != -1)
  {
    X509_EXTENSION *ex = X509_get_ext(x, pos);
    if(ex) {
      ASN1_BIT_STRING *xkeyusage = (ASN1_BIT_STRING *)X509V3_EXT_d2i(ex);
      if(ASN1_BIT_STRING_get_bit(xkeyusage, Bit_DigitalSignature))
        cert->setKeyUsage(DigitalSignature);
      if(ASN1_BIT_STRING_get_bit(xkeyusage, Bit_NonRepudiation))
        cert->setKeyUsage(NonRepudiation);
      if(ASN1_BIT_STRING_get_bit(xkeyusage, Bit_KeyEncipherment))
        cert->setKeyUsage(KeyEncipherment);
      if(ASN1_BIT_STRING_get_bit(xkeyusage, Bit_DataEncipherment))
        cert->setKeyUsage(DataEncipherment);
      if(ASN1_BIT_STRING_get_bit(xkeyusage, Bit_KeyAgreement))
        cert->setKeyUsage(KeyAgreement);
      if(ASN1_BIT_STRING_get_bit(xkeyusage, Bit_KeyCertSign))
        cert->setKeyUsage(KeyCertSign);
      if(ASN1_BIT_STRING_get_bit(xkeyusage, Bit_CRLSign))
        cert->setKeyUsage(CRLSign);
      if(ASN1_BIT_STRING_get_bit(xkeyusage, Bit_EncipherOnly))
        cert->setKeyUsage(EncipherOnly);
      if(ASN1_BIT_STRING_get_bit(xkeyusage, Bit_DecipherOnly))
        cert->setKeyUsage(DecipherOnly);
      ASN1_BIT_STRING_free(xkeyusage);
    }
  }

  pos = X509_get_ext_by_NID(x, NID_ext_key_usage, -1);
  if(pos != -1)
  {
    if ((ex = X509_get_ext(x, pos)) != NULL)
    {
      //FIXME TODO
    }
  }

  // pos = X509_get_ext_by_NID(x, NID_certificate_policies, -1);
  // if(pos != -1)
  // {
  //   X509_EXTENSION *ex = X509_get_ext(x, pos);
  //   if(ex)
  //     p.policies = get_cert_policies(ex);
  // }



  // pos = X509_get_ext_by_NID(x, NID_subject_key_identifier, -1);
  // if(pos != -1)
  // {
  //   X509_EXTENSION *ex = X509_get_ext(x, pos);
  //   if(ex)
  //     p.subjectId += get_cert_subject_key_id(ex);
  // }

  // pos = X509_get_ext_by_NID(x, NID_authority_key_identifier, -1);
  // if(pos != -1)
  // {
  //   X509_EXTENSION *ex = X509_get_ext(x, pos);
  //   if(ex)
  //     p.issuerId += get_cert_issuer_key_id(ex);
  // }

  cert->osslX509 = x;
  cert->derX509 = DER;

  return cert;
}



std::string
X509Cert::toDER() const
{
  if (derX509.size() > 0)
    return derX509;
  throw std::logic_error("X509Cert::toDER");
}
