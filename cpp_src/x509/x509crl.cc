// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2013-2018 ANSSI. All Rights Reserved.
#include <assert.h>
#include <stdexcept>

#include "x509crl.h"

namespace LIBANSSIPKI
{
X509Crl::X509Crl(const X509Cert*  issuer,
                 unsigned int     nextUpdateNbDays,
                 unsigned long    signAlgorithmNID):
  issuer(issuer)
{
  osslX509_CRL = X509_CRL_new();
  if (!osslX509_CRL)
    throw (std::bad_alloc());

  X509_CRL_set_version(osslX509_CRL, 1);

  X509_NAME* issuerName = X509Name(issuer->getSubjectDNString()).toOSSLX509_NAME();
  if (!issuerName)
  {
    X509_CRL_free(osslX509_CRL);
    throw (std::bad_alloc());
  }

  X509_CRL_set_issuer_name(osslX509_CRL,  issuerName);
  X509_NAME_free(issuerName);


  ASN1_TIME* tmptm = ASN1_TIME_new();
  if (!tmptm)
  {
    X509_CRL_free(osslX509_CRL);
    throw (std::bad_alloc());
  }

  X509_gmtime_adj(tmptm,0);
  X509_CRL_set_lastUpdate(osslX509_CRL, tmptm);
  if (!X509_time_adj_ex(tmptm, nextUpdateNbDays, 0, NULL))
  {
    ASN1_TIME_free(tmptm);
    X509_CRL_free(osslX509_CRL);
    throw (std::logic_error("X509_time_adj_ex"));
  }
  X509_CRL_set_nextUpdate(osslX509_CRL, tmptm);

  X509_ALGOR_set0(osslX509_CRL->crl->sig_alg,
    OBJ_nid2obj(signAlgorithmNID), V_ASN1_NULL, NULL);
  X509_ALGOR_set0(osslX509_CRL->sig_alg,
    OBJ_nid2obj(signAlgorithmNID),  V_ASN1_NULL, NULL);
}

X509Crl::~X509Crl()
{
  X509_CRL_free(osslX509_CRL);
}

void
X509Crl::addRevokedCertificate(const std::string& serialNumber,
                               const std::string& revocationTime)
{

  X509_REVOKED*  revoked = NULL;

  revoked = X509_REVOKED_new();
  if (!revoked)
    throw (std::bad_alloc());

  // serial
  BIGNUM* bn = BN_bin2bn((const unsigned char *)serialNumber.c_str(), serialNumber.size(), NULL);
  if (!bn)
    throw (std::bad_alloc());
  BN_to_ASN1_INTEGER(bn, revoked->serialNumber);
  BN_free(bn);

  ASN1_UTCTIME_set_string(revoked->revocationDate, revocationTime.c_str());

  X509_CRL_add0_revoked(osslX509_CRL, revoked);

  X509_CRL_sort(this->osslX509_CRL);
}

std::string
X509Crl::getLastUpdate() const
{
  return std::string((char*)(ASN1_STRING_data(X509_CRL_get_lastUpdate(this->osslX509_CRL))));
}

std::string
X509Crl::dump() const
{
  BIO*  bi = NULL;

  assert(this->osslX509_CRL != 0);

  bi = BIO_new(BIO_s_mem());
  X509_CRL_print(bi, this->osslX509_CRL);
  return bio2string(bi);
}

std::string
X509Crl::toTbsDER() const
{
  unsigned char*  der = NULL;
  size_t      der_length;

  assert(this->osslX509_CRL != 0);

  der_length = ASN1_item_i2d((ASN1_VALUE*)(this->osslX509_CRL->crl),
                &der, ASN1_ITEM_rptr(X509_CRL_INFO));
  std::string res((char*)der, der_length);
  OPENSSL_free(der);

  return res;
}

void
X509Crl::setSignature(const std::string& signature)
{
  ASN1_BIT_STRING_set(this->osslX509_CRL->signature,
    (unsigned char*)(signature.c_str()), signature.size());
  this->osslX509_CRL->signature->flags &= ~(ASN1_STRING_FLAG_BITS_LEFT|0x07);
  this->osslX509_CRL->signature->flags |= ASN1_STRING_FLAG_BITS_LEFT;
}

std::string
X509Crl::toDER() const
{
  assert(this->osslX509_CRL->signature);

  BIO *bo = BIO_new(BIO_s_mem());
  i2d_X509_CRL_bio(bo, this->osslX509_CRL);
  return bio2string(bo);
}

}
