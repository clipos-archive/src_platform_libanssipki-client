// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2013-2018 ANSSI. All Rights Reserved.
#include <assert.h>
#include <stdexcept>
#include "x509tbs.h"
#include "x509cert.h"

using namespace LIBANSSIPKI;

X509Tbs*
X509Tbs::FromX509Req(X509Req*       req,
         const std::string&    notBefore,
         const std::string&    notAfter,
         unsigned long      signAlgorithmNID,
         const std::string&    serialNumber,
         const X509Cert*    issuer) {
  X509Tbs*  tbs = dynamic_cast<X509Tbs*>(req);

  tbs->notBefore = notBefore;
  tbs->notAfter = notAfter;
  tbs->signAlgorithmNID = signAlgorithmNID;
  tbs->serialNumber = serialNumber;
  tbs->issuer = issuer;
  if (issuer)
    tbs->issuerDN = issuer->getSubjectDNString();
  else
    tbs->issuerDN = tbs->getSubjectDNString();

  tbs->generateOSSLX509();

  return tbs;
}

X509Tbs::X509Tbs() :
  serialNumber(""),
  signAlgorithmNID(0),
  notBefore(""),
  notAfter(""),
  issuer(0),
  osslX509(0) {
}

X509Tbs::~X509Tbs() {
  if (this->publicKey)
    delete this->publicKey;
  if (this->osslX509)
    X509_free(this->osslX509);
}

std::string
X509Tbs::dump() const {
  BIO*  bi = NULL;

  assert(this->osslX509 != 0);

  bi = BIO_new(BIO_s_mem());
  X509_print_ex(bi, this->osslX509, X509_FLAG_COMPAT /*XN_FLAG_SEP_MULTILINE*/ ,0);
  return bio2string(bi);
}


std::string
X509Tbs::toDER() const {
  unsigned char*  der = NULL;
  size_t      der_length;

  assert(this->osslX509 != 0);

  der_length = ASN1_item_i2d((ASN1_VALUE*)(this->osslX509->cert_info),
                &der, ASN1_ITEM_rptr(X509_CINF));
  std::string res((char*)der, der_length);
  OPENSSL_free(der);

  return res;
}



unsigned long
X509Tbs::getSignAlgoNID() const {
  return signAlgorithmNID;
}

const std::string&
X509Tbs::getNotBefore() const {
  return notBefore;
}

const std::string&
X509Tbs::getNotAfter() const {
  return notAfter;
}

const std::string&
X509Tbs::getSerialNumber() const {
  return serialNumber;
}

std::string
X509Tbs::getIssuerDNString() const {
  if (issuer)
    return issuer->getSubjectDNString();
  else
    return getSubjectDNString();
}

static X509_EXTENSION*
new_basic_constraints(bool ca, int pathlen)
{
  BASIC_CONSTRAINTS *bs = BASIC_CONSTRAINTS_new();
  bs->ca = (ca ? 0xff: 0);
  if (ca && pathlen > 0)
  {
    bs->pathlen = ASN1_INTEGER_new();
    ASN1_INTEGER_set(bs->pathlen, pathlen);
  }

  X509_EXTENSION *ex = X509V3_EXT_i2d(NID_basic_constraints, 1, bs); // 1 = critical
  BASIC_CONSTRAINTS_free(bs);
  return ex;
}

static X509_EXTENSION*
new_cert_key_usage(const std::set<KeyUsage_e> &constraints)
{
  ASN1_BIT_STRING *keyusage = 0;
  for(std::set<KeyUsage_e>::const_iterator it = constraints.begin();
     it != constraints.end(); ++it)
  {
    int bit = -1;
    switch (*it)
    {
      case DigitalSignature:
        bit = Bit_DigitalSignature;
        break;
      case NonRepudiation:
        bit = Bit_NonRepudiation;
        break;
      case KeyEncipherment:
        bit = Bit_KeyEncipherment;
        break;
      case DataEncipherment:
        bit = Bit_DataEncipherment;
        break;
      case KeyAgreement:
        bit = Bit_KeyAgreement;
        break;
      case KeyCertSign:
        bit = Bit_KeyCertSign;
        break;
      case CRLSign:
        bit = Bit_CRLSign;
        break;
      case EncipherOnly:
        bit = Bit_EncipherOnly;
        break;
      case DecipherOnly:
        bit = Bit_DecipherOnly;
        break;
      default:
        break;
    }
    if(bit != -1)
    {
      if(!keyusage)
        keyusage = ASN1_BIT_STRING_new();
      ASN1_BIT_STRING_set_bit(keyusage, bit, 1);
    }
  }
  if(!keyusage)
    return 0;

  X509_EXTENSION *ex = X509V3_EXT_i2d(NID_key_usage, 1, keyusage); // 1 = critical
  ASN1_BIT_STRING_free(keyusage);
  return ex;
}

static X509_EXTENSION*
new_cert_ext_key_usage(const std::set<ExtendedKeyUsage_e> &constraints)
{
  EXTENDED_KEY_USAGE *extkeyusage = 0;
  for(std::set<ExtendedKeyUsage_e>::const_iterator it = constraints.begin();
     it != constraints.end(); ++it)
  {
    int nid = -1;
    // TODO: don't use known/nid, and instead just use OIDs
    switch (*it)
    {
      case ServerAuth:
        nid = NID_server_auth;
        break;
      case ClientAuth:
        nid = NID_client_auth;
        break;
      case CodeSigning:
        nid = NID_code_sign;
        break;
      case EmailProtection:
        nid = NID_email_protect;
        break;
      case IPSecEndSystem:
        nid = NID_ipsecEndSystem;
        break;
      case IPSecTunnel:
        nid = NID_ipsecTunnel;
        break;
      case IPSecUser:
        nid = NID_ipsecUser;
        break;
      case TimeStamping:
        nid = NID_time_stamp;
        break;
      case OCSPSigning:
        nid = NID_OCSP_sign;
        break;
      default:
        break;
    }
    if(nid != -1)
    {
      if(!extkeyusage)
        extkeyusage = sk_ASN1_OBJECT_new_null();
      ASN1_OBJECT *obj = OBJ_nid2obj(nid);
      sk_ASN1_OBJECT_push(extkeyusage, obj);
    }
  }
  if(!extkeyusage)
    return 0;

  X509_EXTENSION *ex = X509V3_EXT_i2d(NID_ext_key_usage, 0, extkeyusage); // 0 = not critical
  sk_ASN1_OBJECT_pop_free(extkeyusage, ASN1_OBJECT_free);
  return ex;
}

static GENERAL_NAME*
new_general_name(SAN_e type, const std::string &val)
{
  GENERAL_NAME *name = 0;
  switch(type)
  {
    case SAN_Email: //rfc822Name
    {
      ASN1_IA5STRING *str = M_ASN1_IA5STRING_new();
      ASN1_STRING_set((ASN1_STRING *)str, (unsigned char *)val.c_str(), val.size());

      name = GENERAL_NAME_new();
      name->type = GEN_EMAIL;
      name->d.rfc822Name = str;
      break;
    }
    case SAN_URI: //uniformResourceIdentifier
    {
      ASN1_IA5STRING *str = M_ASN1_IA5STRING_new();
      ASN1_STRING_set((ASN1_STRING *)str, (unsigned char *)val.c_str(), val.size());

      name = GENERAL_NAME_new();
      name->type = GEN_URI;
      name->d.uniformResourceIdentifier = str;
      break;
    }
    case SAN_DNS: //dNSName
    {
      ASN1_IA5STRING *str = M_ASN1_IA5STRING_new();
      ASN1_STRING_set((ASN1_STRING *)str, (unsigned char *)val.c_str(), val.size());

      name = GENERAL_NAME_new();
      name->type = GEN_DNS;
      name->d.dNSName = str;
      break;
    }
    case SAN_IPAddress: //IPAddress
    {
      ASN1_OCTET_STRING *ostr = a2i_IPADDRESS(val.c_str());
      if (!ostr)
        throw std::logic_error("Invalid IPAddress in Subject Alternative Name");
      name = GENERAL_NAME_new();
      name->type = GEN_IPADD;
      name->d.iPAddress = ostr;
      break;
    }
    default:
      break;
  }
  return name;
}

static void
try_add_general_name(GENERAL_NAMES **gn, SAN_e type, const std::string &val)
{
  if(val == "")
    return;
  GENERAL_NAME *name = new_general_name(type, val);
  if(name)
  {
    if(!(*gn))
      *gn = sk_GENERAL_NAME_new_null();
    sk_GENERAL_NAME_push(*gn, name);
  }
}

static X509_EXTENSION*
new_cert_subject_alt_name(std::list<std::pair<SAN_e, std::string> > SANs)
{
  GENERAL_NAMES *gn = 0;

  for (std::list<std::pair<SAN_e, std::string> >::const_iterator it = SANs.begin();
    it != SANs.end(); ++it)
      try_add_general_name(&gn, it->first, it->second);

  if(!gn)
    return 0;

  X509_EXTENSION *ex = X509V3_EXT_i2d(NID_subject_alt_name, 0, gn);
  sk_GENERAL_NAME_pop_free(gn, GENERAL_NAME_free);
  return ex;
}

// From openssl/crypto/x509v3/v3_skey.c
static X509_EXTENSION*
new_cert_ski(X509_PUBKEY* pk) {
  ASN1_OCTET_STRING *oct;
  unsigned char pkey_dig[EVP_MAX_MD_SIZE];
  unsigned int diglen;

  if (!(oct = M_ASN1_OCTET_STRING_new()))
    throw std::logic_error("X509V3err(X509V3_F_S2I_SKEY_ID,ERR_R_MALLOC_FAILURE);");

  if (!EVP_Digest(pk->public_key->data, pk->public_key->length, pkey_dig, &diglen, EVP_sha1(), NULL))
    throw std::logic_error("generate_ski EVP_Digest Failure");

  if (!M_ASN1_OCTET_STRING_set(oct, pkey_dig, diglen))
    throw std::logic_error("X509V3err(X509V3_F_S2I_SKEY_ID,ERR_R_MALLOC_FAILURE);");


  X509_EXTENSION *ex = X509V3_EXT_i2d(NID_subject_key_identifier, 0, oct); // 0 = non-critical

  M_ASN1_OCTET_STRING_free(oct);

  return ex;
}


// From openssl/crypto/x509v3/v3_akey.c
static X509_EXTENSION*
new_cert_aki(X509* issuer) {
  ASN1_OCTET_STRING *ikeyid = 0;
  X509_EXTENSION *ext = 0;
  AUTHORITY_KEYID *akeyid = 0;

  if (!issuer)
    return 0;

  int i = X509_get_ext_by_NID(issuer, NID_subject_key_identifier, -1);
  if((i >= 0)  && (ext = X509_get_ext(issuer, i)))
    ikeyid = (ASN1_OCTET_STRING*)X509V3_EXT_d2i(ext);
  assert(ikeyid != 0);

  if (!(akeyid = AUTHORITY_KEYID_new()))
    throw std::logic_error("AUTHORITY_KEYID_new Failure");

  akeyid->keyid = ikeyid;
  akeyid->issuer = 0;
  akeyid->serial = 0;

  ext = X509V3_EXT_i2d(NID_authority_key_identifier, 0, akeyid);

  return ext;
}


static X509_EXTENSION*
new_cert_policies(std::list<std::pair<std::string, std::string> > policies) {
  STACK_OF(POLICYINFO) *pols = NULL;
  POLICYINFO *pol;
  POLICYQUALINFO *qual;
  ASN1_OBJECT *pobj;

  pols = sk_POLICYINFO_new_null();

  if (policies.size() == 0)
  {
    // Add anyPolicy
    pobj = OBJ_txt2obj("anyPolicy", 0);
    pol = POLICYINFO_new();
    pol->policyid = pobj;
    sk_POLICYINFO_push(pols, pol);
  }
  else
  {
    for (std::list<std::pair<std::string, std::string> >::const_iterator iter = policies.begin();
      iter != policies.end(); iter++)
    {
      pobj = OBJ_txt2obj(iter->first.c_str(), 0);
      pol = POLICYINFO_new();
      pol->policyid = pobj;

      if (iter->second != "")
      {
        if(!pol->qualifiers) pol->qualifiers =
           sk_POLICYQUALINFO_new_null();
        qual = POLICYQUALINFO_new();
        qual->pqualid = OBJ_nid2obj(NID_id_qt_cps);
        qual->d.cpsuri = M_ASN1_IA5STRING_new();
        ASN1_STRING_set(qual->d.cpsuri, iter->second.c_str(),
               iter->second.length());
        sk_POLICYQUALINFO_push(pol->qualifiers, qual);
      }
      sk_POLICYINFO_push(pols, pol);
    }
  }

  X509_EXTENSION *ex = X509V3_EXT_i2d(NID_certificate_policies, 0, pols); // 0 = non-critical

  sk_POLICYINFO_pop_free(pols, POLICYINFO_free);

  return ex;
}

static bool
parseOSSLextensionConf (const std::string& content, X509* x509) {
  BIO*   contentBio = string2bio (std::string("[v3_exts]\n") + content);
  CONF*  config=NCONF_new(NULL);
  long errline = -1;

  if (!config)
    throw std::bad_alloc();

  if (!NCONF_load_bio(config, contentBio, &errline))
  {
    NCONF_free(config);
    throw std::invalid_argument("Error NCONF_load_bio");
  }
  /* Check syntax of file */
  X509V3_CTX ctx;
  X509V3_set_ctx_test(&ctx);
  X509V3_set_nconf(&ctx, config);
  if(!X509V3_EXT_add_nconf(config, &ctx, (char*)"v3_exts", x509))
  {
    NCONF_free(config);
    throw std::invalid_argument("Error Loading extension section");
  }

  return 1;
}

void
X509Tbs::generateOSSLX509() {
  X509_EXTENSION*  ex;

  // create
  X509* x = X509_new();
  if (!x)
    throw std::bad_alloc();

  // set version to 3 (value 2)
  X509_set_version(x, 2);

  // public key
  X509_set_pubkey(x, publicKey->pkey);

  // subject
  X509_NAME *name = subjectDN.toOSSLX509_NAME();
  if (!name)
    throw std::bad_alloc();
  X509_set_subject_name(x, name);
  X509_NAME_free(name);

  // issuer
  X509_NAME *issuerName = X509Name(issuerDN).toOSSLX509_NAME();
  if (!issuerName)
    throw std::bad_alloc();
  X509_set_issuer_name(x, issuerName);
  X509_NAME_free(issuerName);

  // CA mode
  ex = new_basic_constraints(isCA(), caPathLimit);
  if(ex)
  {
    X509_add_ext(x, ex, -1);
    X509_EXTENSION_free(ex);
  }

  // subject alt name
  ex = new_cert_subject_alt_name(SANs);
  if(ex)
  {
    X509_add_ext(x, ex, -1);
    X509_EXTENSION_free(ex);
  }

  // key usage
  ex = new_cert_key_usage(keyUsages);
  if(ex)
  {
    X509_add_ext(x, ex, -1);
    X509_EXTENSION_free(ex);
  }

  // extended key usage
  ex = new_cert_ext_key_usage(extKeyUsages);
  if(ex)
  {
    X509_add_ext(x, ex, -1);
    X509_EXTENSION_free(ex);
  }

  // policies
  ex = new_cert_policies(policies);
  if(ex)
  {
    X509_add_ext(x, ex, -1);
    X509_EXTENSION_free(ex);
  }

  // ski
  ex = new_cert_ski(x->cert_info->key);
  if(ex)
  {
    X509_add_ext(x, ex, -1);
    X509_EXTENSION_free(ex);
  }

  // aki
  if (issuer)
  {
    ex = new_cert_aki(issuer->osslX509);
    if(ex)
    {
      X509_add_ext(x, ex, -1);
      X509_EXTENSION_free(ex);
    }
  }

  for (std::list<std::string>::const_iterator iter = genericOSSLExtensions.begin();
    iter != genericOSSLExtensions.end(); iter++)
  {
    parseOSSLextensionConf(*iter, x);
  }

  // serial
  BIGNUM* bn = BN_bin2bn((const unsigned char *)serialNumber.c_str(), serialNumber.size(), NULL);
  if (!bn)
    throw std::bad_alloc();
  BN_to_ASN1_INTEGER(bn, X509_get_serialNumber(x));
  BN_free(bn);

  // validity period
  ASN1_UTCTIME_set_string(X509_get_notBefore(x), notBefore.c_str());
  ASN1_UTCTIME_set_string(X509_get_notAfter(x), notAfter.c_str());

  X509_ALGOR_set0(x->cert_info->signature,
    OBJ_nid2obj(signAlgorithmNID), V_ASN1_NULL, NULL);
  X509_ALGOR_set0(x->sig_alg,
    OBJ_nid2obj(signAlgorithmNID), V_ASN1_NULL, NULL);

  this->osslX509 = x;
}
