// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2013-2018 ANSSI. All Rights Reserved.
#include <string.h>
#include <sys/stat.h>
#include <openssl/pkcs12.h>
#include <stdexcept>

#include "p11-exception.h"
#include "p11-helper.h"
#include "algos.h"

using namespace LIBANSSIPKI;

extern "C" {
  void *C_LoadModule(const char *name, CK_FUNCTION_LIST_PTR_PTR);
  CK_RV C_UnloadModule(void *module);
}

static const char *p11_utf8_to_local(CK_UTF8CHAR *string, size_t len);

static CK_BBOOL _true = TRUE;
static CK_BBOOL _false = FALSE;

#define FILL_ATTR(attr, typ, val, len) {(attr).type=(typ); (attr).pValue=(val); (attr).ulValueLen=len;}


P11Helper* P11Helper::instance = 0;

P11Helper*
P11Helper::connect(const std::string& module_path,
           const char*      pin,
           const std::string&  label,
           bool         force_slot_id,
           unsigned long     slot_id)
{
  P11Helper* p11h = new P11Helper();

  if (! p11h->loadModule(module_path))
  {
    delete p11h;
    return NULL;
  }

  if (force_slot_id)
  {
    if (! p11h->openTokenWithSlotId(slot_id))
    {
      delete p11h;
      return NULL;
    }
  }
  else
    if (! p11h->openTokenWithLabel(label))
    {
      delete p11h;
      return NULL;
    }

  p11h->fillMechanismList();

  try {
    p11h->login(CKU_USER, pin);
  }
  catch (P11Exception& e) {
    delete p11h;
    throw e;
  }
  return p11h;
}

void
P11Helper::initInstance(P11Helper* p11)
{
  P11Helper::instance = p11;
}

P11Helper*
P11Helper::getInstance()
{
  return P11Helper::instance;
}

void
P11Helper::closeInstance()
{
  if (P11Helper::instance)
  {
    delete P11Helper::instance;
    P11Helper::instance = 0;
  }
}

P11Helper::P11Helper()
  : module(0),
  p11_slots(0),
  p11_num_slots(0),
  hSession(0),
  current_slot(0)
{
}

P11Helper::~P11Helper()
{
  if (p11_slots)
    delete[] (p11_slots);
  if (p11)
    p11->C_Finalize(NULL_PTR);
  if (module)
    C_UnloadModule(module);
}

bool
P11Helper::loadModule(const std::string& modulePath)
{
  CK_RV  rv;
  struct stat buffer;

  if (stat (modulePath.c_str(), &buffer) != 0)
  	throw std::logic_error(modulePath + " does not exists.");

  module = C_LoadModule(modulePath.c_str(), &p11);
  if (module == NULL)
  	throw std::logic_error("Failed to load pkcs11 module");

  rv = p11->C_Initialize(NULL);
  if (rv != CKR_OK)
    throw P11Exception(rv, "C_Initialize()");

  return TRUE;
}

void
P11Helper::login(int login_type /* CKU_SO or CKU_USER or CKU_CONTEXT_SPECIFIC */,
         const char *pin)
{
  CK_RV    rv;

  rv = p11->C_OpenSession(current_slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
            NULL, NULL, &hSession);
  if (rv != CKR_OK)
    throw P11Exception(rv, "C_OpenSession()");

  rv = p11->C_Login(hSession, login_type,
      (unsigned char*)pin, pin == NULL ? 0 : strlen(pin));
  if (rv != CKR_OK)
    throw P11Exception(rv, "C_Login()");
}


void
P11Helper::fetchSlots() {
  CK_RV  rv;

  // Récuperer tous les slots avec au moins un token présent
  rv = p11->C_GetSlotList(CK_TRUE, NULL, &p11_num_slots);
  if (rv != CKR_OK)
    throw P11Exception(rv, "C_GetSlotList(NULL)");
  p11_slots = new CK_SLOT_ID[p11_num_slots]();

  rv = p11->C_GetSlotList(CK_TRUE, p11_slots, &p11_num_slots);
  if (rv != CKR_OK)
    throw P11Exception(rv, "C_GetSlotList()");
}

bool
P11Helper::openTokenWithSlotId(unsigned long id) {
  CK_ULONG  n;

  if (p11_num_slots == 0)
    fetchSlots();

  for (n = 0; n < p11_num_slots; n++) {
    if (p11_slots[n] == id )
    {
      current_slot = p11_slots[n];
      return true;
    }
  }

  return false;
}

bool
P11Helper::openTokenWithLabel(const std::string& label) {
  CK_TOKEN_INFO  info;
  CK_ULONG  n;
  CK_RV    rv;

  if (p11_num_slots == 0)
    fetchSlots();

  for (n = 0; n < p11_num_slots; n++) {
    std::string token_label;

    rv = p11->C_GetTokenInfo(p11_slots[n], &info);
    if (rv != CKR_OK)
      continue;
    token_label = std::string(p11_utf8_to_local(info.label, sizeof(info.label)));
    if (token_label == label) {
      current_slot = p11_slots[n];
      return true;
    }
  }

  return false;
}

void
P11Helper::fillMechanismList() {
  CK_MECHANISM_TYPE_PTR pList = NULL;
  CK_ULONG  ulCount = 0;
  CK_RV    rv;

  rv = p11->C_GetMechanismList(current_slot, pList, &ulCount);
  pList = new CK_MECHANISM_TYPE[ulCount];

  rv = p11->C_GetMechanismList(current_slot, pList, &ulCount);
  if (rv != CKR_OK)
    throw P11Exception(rv, "C_GetMechanismList()");

  CK_MECHANISM_INFO info;

  for (CK_ULONG n = 0; n < ulCount; n++) {
    rv = p11->C_GetMechanismInfo(current_slot, pList[n], &info);
    if (rv != CKR_OK)
      continue;
    if (info.flags & CKF_SIGN)
      signMechanisms.push_back(pList[n]);
  }

  delete pList;
}


template <typename TYPE> TYPE
P11Helper::getAttr(CK_ULONG cka_value, CK_OBJECT_HANDLE obj)
{
  TYPE    type = 0;
  CK_ATTRIBUTE  attr = { cka_value, &type, sizeof(type) };
  CK_RV    rv;

  rv = p11->C_GetAttributeValue(hSession, obj, &attr, 1);
  if (rv != CKR_OK)
    throw P11Exception(rv, "C_GetAttributeValue", cka_value);
  return type;
}

template <typename TYPE> void
P11Helper::getAttr(CK_ULONG cka_value, CK_OBJECT_HANDLE obj, TYPE*& data, CK_ULONG& size)
{
  CK_ATTRIBUTE  attr = { cka_value, NULL, 0 };
  CK_RV    rv;

  rv = p11->C_GetAttributeValue(hSession, obj, &attr, 1);
  if (rv == CKR_OK) {
    attr.pValue = malloc(attr.ulValueLen);
    rv = p11->C_GetAttributeValue(hSession, obj, &attr, 1);
    size = attr.ulValueLen / sizeof(TYPE);
    data = (TYPE*)attr.pValue;
  }
  else
    throw P11Exception(rv, "C_GetAttributeValue", cka_value);
}


std::list<std::string>
P11Helper::listAvailableSignAlgorithms() const
{
  std::list<std::string> signAlgorithmsStrList;

  for (std::list<CK_MECHANISM_TYPE>::const_iterator iter = signMechanisms.begin();
     iter != signMechanisms.end(); iter++)
  {
    const char* str = SignAlgoP11MechToString(*iter);
    if (str)
      signAlgorithmsStrList.push_back(std::string(str));
  }
  return signAlgorithmsStrList;
}


std::string
P11Helper::generateRandom(size_t size)
{
  std::string res;

  res.resize(size);
  generateRandom((unsigned char*)res.c_str(), size);
  return res;
}

void
P11Helper::generateRandom(unsigned char* buffer, size_t size)
{
  CK_RV rv;

  //FIXME : seed ? C_SeedRandom

  rv = p11->C_GenerateRandom(hSession, buffer, size);
  if (rv != CKR_OK)
    throw P11Exception(rv, "C_GenerateRandom()");
}

void
P11Helper::createObject(CK_ATTRIBUTE*      objectTemplate,
                        unsigned long      objectTemplateLength,
                        CK_OBJECT_HANDLE*  hObject)
{
  CK_RV rv;

  rv = p11->C_CreateObject(hSession, objectTemplate, objectTemplateLength, hObject);
  if (rv != CKR_OK)
    throw P11Exception(rv, "C_CreateObject()");
}

void
P11Helper::writeCertificate(const X509Cert& cert,
			    unsigned int cryptoID,
			    const std::string& label)
{
  CK_RV rv;
  CK_ATTRIBUTE certTemplate[20];
  CK_OBJECT_CLASS certObjectClass = CKO_CERTIFICATE;
  CK_CERTIFICATE_TYPE certType = CKC_X_509;
  CK_OBJECT_HANDLE hCertificate = CK_INVALID_HANDLE;
  std::string subjectDER = cert.getSubjectDNDER();
  std::string certDER = cert.toDER();

  // Dans un premier temps, si le certificat existe, on le supprime.
  while (this->getObjectHandleByID(CKO_CERTIFICATE, cryptoID, &hCertificate))
  {
    rv = p11->C_DestroyObject(hSession, hCertificate);
    if (rv != CKR_OK)
      throw P11Exception(rv, "C_DestroyObject");
  }

  // Et on l'injecte dans la base PKCS#11
  FILL_ATTR(certTemplate[0], CKA_TOKEN, &_true, sizeof(_true));
  FILL_ATTR(certTemplate[1], CKA_VALUE, (char*)(certDER.c_str()), certDER.size());
  FILL_ATTR(certTemplate[2], CKA_CLASS, &certObjectClass, sizeof(certObjectClass));
  FILL_ATTR(certTemplate[3], CKA_CERTIFICATE_TYPE, &certType, sizeof(certType));
  FILL_ATTR(certTemplate[4], CKA_ID, (void*)&cryptoID, sizeof(unsigned int));
  FILL_ATTR(certTemplate[5], CKA_LABEL, (void*)label.c_str(), label.size());
  /* pkcs11-tool.c -> according to PKCS #11 CKA_SUBJECT MUST be specified */
  FILL_ATTR(certTemplate[6], CKA_SUBJECT, (char*)(subjectDER.c_str()), subjectDER.size());

  rv = p11->C_CreateObject(hSession, (CK_ATTRIBUTE*)&certTemplate, 7, &hCertificate);
  if (rv != CKR_OK)
    throw P11Exception(rv, "C_CreateObject");
}

int
P11Helper::getObjectHandleByLabel(const CK_OBJECT_CLASS cls,
                  const std::string    label,
                  CK_OBJECT_HANDLE*    ret)
{
  CK_ATTRIBUTE attrs[2];
  unsigned int nattrs = 0;
  CK_ULONG count = 1;
  CK_RV rv;

  attrs[0].type = CKA_CLASS;
  attrs[0].pValue = (CK_OBJECT_CLASS*)&cls;
  attrs[0].ulValueLen = sizeof(cls);
  nattrs++;

  attrs[nattrs].type = CKA_LABEL;
  attrs[nattrs].pValue = (void *) label.c_str();
  attrs[nattrs].ulValueLen = label.length();
  nattrs++;

  rv = p11->C_FindObjectsInit(hSession, attrs, nattrs);
  if (rv != CKR_OK)
    throw P11Exception(rv, "C_FindObjectsInit");

  rv = p11->C_FindObjects(hSession, ret, 1, &count);
  if (rv != CKR_OK)
    throw P11Exception(rv, "C_FindObjects");

  p11->C_FindObjectsFinal(hSession);

  return count;
}

int
P11Helper::findCertificateBySubject(const std::string&   subject,
                  CK_OBJECT_HANDLE*    ret)
{
  //  CK_ATTRIBUTE attrs[3]; // No label
  CK_ATTRIBUTE attrs[2];
  unsigned int nattrs = 0;
  CK_ULONG count = 1;
  CK_RV rv;
  //std::string label = std::string("ANSSIPKI");
  CK_OBJECT_CLASS certObjectClass = CKO_CERTIFICATE;

  attrs[0].type = CKA_CLASS;
  attrs[0].pValue = &certObjectClass;
  attrs[0].ulValueLen = sizeof(certObjectClass);
  nattrs++;

  //attrs[nattrs].type = CKA_LABEL;
  //attrs[nattrs].pValue = (void *) label.c_str();
  //attrs[nattrs].ulValueLen = label.length();
  //nattrs++;

  attrs[nattrs].type = CKA_SUBJECT;
  attrs[nattrs].pValue = (void *) subject.c_str();
  attrs[nattrs].ulValueLen = subject.length();
  nattrs++;

  rv = p11->C_FindObjectsInit(hSession, attrs, nattrs);
  if (rv != CKR_OK)
    throw P11Exception(rv, "C_FindObjectsInit");

  rv = p11->C_FindObjects(hSession, ret, 1, &count);
  if (rv != CKR_OK)
    throw P11Exception(rv, "C_FindObjects");

  p11->C_FindObjectsFinal(hSession);

  return count;
}

int
P11Helper::getObjectHandleByID(const CK_OBJECT_CLASS cls,
                 const unsigned int    id,
                 CK_OBJECT_HANDLE*     ret)
{
  CK_ATTRIBUTE attrs[2];
  unsigned int nattrs = 0;
  CK_ULONG count = 1;
  CK_RV rv;

  attrs[0].type = CKA_CLASS;
  attrs[0].pValue = (CK_OBJECT_CLASS*)&cls;
  attrs[0].ulValueLen = sizeof(cls);
  nattrs++;

  attrs[nattrs].type = CKA_ID;
  attrs[nattrs].pValue = (void *)&id;
  attrs[nattrs].ulValueLen = sizeof(unsigned int);
  nattrs++;

  rv = p11->C_FindObjectsInit(hSession, attrs, nattrs);
  if (rv != CKR_OK)
    throw P11Exception(rv, "C_FindObjectsInit");

  rv = p11->C_FindObjects(hSession, ret, 1, &count);
  if (rv != CKR_OK)
    throw P11Exception(rv, "C_FindObjects");

  p11->C_FindObjectsFinal(hSession);

  return count;
}

void
P11Helper::generateRSAKeyPair(const CK_ULONG key_length,
                const unsigned long  id,
                const bool      sensitive,
		const std::string&   label,
	        const keyUsage       usage,
                CK_OBJECT_HANDLE*    hPublicKey,
                CK_OBJECT_HANDLE*    hPrivateKey)
{
  CK_MECHANISM mechanism = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0};
  CK_ULONG modulusBits = 1024;
  CK_BYTE publicExponent[] = { 0x01, 0x00, 0x01 }; /* 65537 in bytes */
  CK_OBJECT_CLASS pubkey_class = CKO_PUBLIC_KEY;
  CK_OBJECT_CLASS privkey_class = CKO_PRIVATE_KEY;
  CK_ATTRIBUTE publicKeyTemplate[20] = {
    {CKA_CLASS, &pubkey_class, sizeof(pubkey_class)},
    {CKA_LABEL, (void*)label.c_str(), label.size()},
    {CKA_TOKEN, &_true, sizeof(CK_BBOOL)},
    {CKA_WRAP, &_false, sizeof(CK_BBOOL)},
  };
  int n_pubkey_attr = 4;
  CK_ATTRIBUTE privateKeyTemplate[20] = {
    {CKA_CLASS, &privkey_class, sizeof(privkey_class)},
    {CKA_TOKEN, &_true, sizeof(CK_BBOOL)},
    {CKA_LABEL, (void*)label.c_str(), label.size()},
    {CKA_PRIVATE, &_true, sizeof(CK_BBOOL)},
    // TODO : Better handling of sensitive / extractable
    {CKA_SENSITIVE, (sensitive)? &_true : &_false, sizeof(CK_BBOOL)},
    {CKA_EXTRACTABLE, (!sensitive)? &_true : &_false, sizeof(CK_BBOOL)},
    {CKA_UNWRAP, &_false, sizeof(CK_BBOOL)}
  };
  int n_privkey_attr = 7;
  CK_RV rv;

  if (usage == USAGE_SIGNATURE)
    {
      // Public key
      FILL_ATTR(publicKeyTemplate[n_pubkey_attr], CKA_VERIFY,
		&_true, sizeof(CK_BBOOL));
      n_pubkey_attr++;  
      FILL_ATTR(publicKeyTemplate[n_pubkey_attr], CKA_VERIFY_RECOVER,
		&_false, sizeof(CK_BBOOL));
      n_pubkey_attr++;
      FILL_ATTR(publicKeyTemplate[n_pubkey_attr], CKA_ENCRYPT,
		&_false, sizeof(CK_BBOOL));
      n_pubkey_attr++;
      // Private key
      FILL_ATTR(privateKeyTemplate[n_privkey_attr], CKA_SIGN,
		&_true, sizeof(CK_BBOOL));
      n_privkey_attr++;  
      FILL_ATTR(privateKeyTemplate[n_privkey_attr], CKA_SIGN_RECOVER,
		&_false, sizeof(CK_BBOOL));
      n_privkey_attr++;
      FILL_ATTR(privateKeyTemplate[n_privkey_attr], CKA_DECRYPT,
		&_false, sizeof(CK_BBOOL));
      n_privkey_attr++;
    }
  else if (usage == USAGE_ENCRYPTION)
    {
      // Public key
      FILL_ATTR(publicKeyTemplate[n_pubkey_attr], CKA_VERIFY,
		&_false, sizeof(CK_BBOOL));
      n_pubkey_attr++;  
      FILL_ATTR(publicKeyTemplate[n_pubkey_attr], CKA_VERIFY_RECOVER,
		&_false, sizeof(CK_BBOOL));
      n_pubkey_attr++;
      FILL_ATTR(publicKeyTemplate[n_pubkey_attr], CKA_ENCRYPT,
		&_true, sizeof(CK_BBOOL));
      n_pubkey_attr++;
      // Private key
      FILL_ATTR(privateKeyTemplate[n_privkey_attr], CKA_SIGN,
		&_false, sizeof(CK_BBOOL));
      n_privkey_attr++;  
      FILL_ATTR(privateKeyTemplate[n_privkey_attr], CKA_SIGN_RECOVER,
		&_false, sizeof(CK_BBOOL));
      n_privkey_attr++;
      FILL_ATTR(privateKeyTemplate[n_privkey_attr], CKA_DECRYPT,
		&_true, sizeof(CK_BBOOL));
      n_privkey_attr++;
    }
  else
    {
      throw P11Exception(CKR_TEMPLATE_INCONSISTENT, "C_GenerateKeyPair");
    }
  
  modulusBits = key_length;

  FILL_ATTR(publicKeyTemplate[n_pubkey_attr], CKA_MODULUS_BITS,
    &modulusBits, sizeof(modulusBits));
  n_pubkey_attr++;
  FILL_ATTR(publicKeyTemplate[n_pubkey_attr], CKA_PUBLIC_EXPONENT,
    publicExponent, sizeof(publicExponent));
  n_pubkey_attr++;
  FILL_ATTR(publicKeyTemplate[n_pubkey_attr], CKA_ID,
		(char*)&id, sizeof(unsigned int));
  FILL_ATTR(privateKeyTemplate[n_privkey_attr], CKA_ID,
		(char*)&id, sizeof(unsigned int));
  n_pubkey_attr++;
  n_privkey_attr++;

  rv = p11->C_GenerateKeyPair(hSession, &mechanism,
    publicKeyTemplate, n_pubkey_attr,
    privateKeyTemplate, n_privkey_attr,
    hPublicKey, hPrivateKey);

  if (rv != CKR_OK)
    throw P11Exception(rv, "C_GenerateKeyPair");
}

void
P11Helper::generateECKeyPair(const std::string& ecparams,
               const unsigned int  id,
               const bool      sensitive,
               CK_OBJECT_HANDLE*  hPublicKey,
               CK_OBJECT_HANDLE*  hPrivateKey)
{
  CK_MECHANISM mechanism = {CKM_EC_KEY_PAIR_GEN, NULL_PTR, 0};
  CK_OBJECT_CLASS pubkey_class = CKO_PUBLIC_KEY;
  CK_OBJECT_CLASS privkey_class = CKO_PRIVATE_KEY;
  CK_ATTRIBUTE publicKeyTemplate[20] = {
    {CKA_CLASS, &pubkey_class, sizeof(pubkey_class)},
    {CKA_TOKEN, &_true, sizeof(CK_BBOOL)},
    {CKA_ENCRYPT, &_false, sizeof(CK_BBOOL)},
    {CKA_VERIFY, &_true, sizeof(CK_BBOOL)},
    {CKA_WRAP, &_false, sizeof(CK_BBOOL)},
  };
  int n_pubkey_attr = 5;
  CK_ATTRIBUTE privateKeyTemplate[20] = {
    {CKA_CLASS, &privkey_class, sizeof(privkey_class)},
    {CKA_TOKEN, &_true, sizeof(CK_BBOOL)},
    {CKA_PRIVATE, &_true, sizeof(CK_BBOOL)},
    {CKA_SENSITIVE, (sensitive)? &_true : &_false, sizeof(CK_BBOOL)},
    {CKA_EXTRACTABLE, (!sensitive)? &_true : &_false, sizeof(CK_BBOOL)},
    {CKA_DECRYPT, &_false, sizeof(CK_BBOOL)},
    {CKA_SIGN, &_true, sizeof(CK_BBOOL)},
    {CKA_UNWRAP, &_false, sizeof(CK_BBOOL)}
  };
  int n_privkey_attr = 8;
  CK_RV rv;

  FILL_ATTR(publicKeyTemplate[n_pubkey_attr], CKA_EC_PARAMS, (void*)ecparams.c_str(), ecparams.size());
  n_pubkey_attr++;

  FILL_ATTR(publicKeyTemplate[n_pubkey_attr], CKA_ID,
    (char*)&id, sizeof(unsigned int));
  FILL_ATTR(privateKeyTemplate[n_privkey_attr], CKA_ID,
    (char*)&id, sizeof(unsigned int));
  n_pubkey_attr++;
  n_privkey_attr++;

  rv = p11->C_GenerateKeyPair(hSession, &mechanism,
    publicKeyTemplate, n_pubkey_attr,
    privateKeyTemplate, n_privkey_attr,
    hPublicKey, hPrivateKey);

  if (rv != CKR_OK)
    throw P11Exception(rv, "C_GenerateKeyPair");
}

PublicKey*
P11Helper::extractPublicKey(CK_OBJECT_HANDLE obj)
{
  CK_KEY_TYPE  key_type = getAttr<CK_KEY_TYPE> (CKA_KEY_TYPE, obj);
  CK_OBJECT_CLASS clazz = getAttr<CK_OBJECT_CLASS> (CKA_CLASS, obj);

  if (clazz != CKO_PUBLIC_KEY)
    throw std::invalid_argument("P11Helper::extractPublicKey : object key type invalid");

  if (key_type == CKK_RSA)
  {
    char*    data = NULL;
    CK_ULONG  dataLen = 0;
    getAttr<char>(CKA_MODULUS, obj, data, dataLen);
    std::string modulus (data, dataLen);
    free(data);
    data = NULL;
    getAttr<char>(CKA_PUBLIC_EXPONENT, obj, data, dataLen);
    std::string publicExponent (data, dataLen);
    free(data);
    data = NULL;
    return new RSAPublicKey(modulus, publicExponent);
  }
  else
    throw std::invalid_argument("P11Helper::extractPublicKey");
}

RSAPrivateKey*
P11Helper::extractRSAPrivateKey(CK_OBJECT_HANDLE  obj)
{
  CK_KEY_TYPE  key_type = getAttr<CK_KEY_TYPE> (CKA_KEY_TYPE, obj);
  CK_OBJECT_CLASS clazz = getAttr<CK_OBJECT_CLASS> (CKA_CLASS, obj);

  if (clazz != CKO_PRIVATE_KEY)
    throw std::invalid_argument("P11Helper::extractRSAPrivateKey : object key type invalid");

  if (key_type == CKK_RSA)
  {
    char*    data = NULL;
    CK_ULONG  dataLen = 0;
    // Modulus
    getAttr<char>(CKA_MODULUS, obj, data, dataLen);
    std::string modulus (data, dataLen);
    free(data);
    data = NULL;
    // Public exponent
    getAttr<char>(CKA_PUBLIC_EXPONENT, obj, data, dataLen);
    std::string publicExponent (data, dataLen);
    free(data);
    data = NULL;
    // Private exponent
    getAttr<char>(CKA_PRIVATE_EXPONENT, obj, data, dataLen);
    std::string privateExponent (data, dataLen);
    free(data);
    data = NULL;
    // P
    getAttr<char>(CKA_PRIME_1, obj, data, dataLen);
    std::string p (data, dataLen);
    free(data);
    data = NULL;
    // Q
    getAttr<char>(CKA_PRIME_2, obj, data, dataLen);
    std::string q (data, dataLen);
    free(data);
    data = NULL;
    // DMP1
    getAttr<char>(CKA_EXPONENT_1, obj, data, dataLen);
    std::string dmp1 (data, dataLen);
    free(data);
    data = NULL;
    // DMQ1
    getAttr<char>(CKA_EXPONENT_2, obj, data, dataLen);
    std::string dmq1 (data, dataLen);
    free(data);
    data = NULL;
    // IQMP
    getAttr<char>(CKA_COEFFICIENT, obj, data, dataLen);
    std::string iqmp (data, dataLen);
    free(data);
    data = NULL;
    return new RSAPrivateKey(modulus, publicExponent, privateExponent,
			    p, q, dmp1, dmq1, iqmp);
  }
  else
    throw std::invalid_argument("P11Helper::extractRSAPrivateKey");  
}

void
P11Helper::writeRSAPrivateKey(const RSAPrivateKey& key,
			   const unsigned long  id,
			   const bool           sensitive,
			   const std::string&   label,
			   const keyUsage       usage)
{
  CK_RV rv;
  CK_ATTRIBUTE keyTemplate[20];
  CK_OBJECT_CLASS privObjectClass = CKO_PRIVATE_KEY;
  CK_OBJECT_CLASS pubObjectClass = CKO_PUBLIC_KEY;
  CK_KEY_TYPE keyType = CKK_RSA;
  CK_OBJECT_HANDLE h;

  // Clé privée
  FILL_ATTR(keyTemplate[0], CKA_TOKEN, &_true, sizeof(_true));
  FILL_ATTR(keyTemplate[1], CKA_CLASS, &privObjectClass, sizeof(privObjectClass));
  FILL_ATTR(keyTemplate[2], CKA_KEY_TYPE, &keyType, sizeof(keyType));
  FILL_ATTR(keyTemplate[3], CKA_ID, (void*)&id, sizeof(unsigned int));
  FILL_ATTR(keyTemplate[4], CKA_LABEL, (void*)label.c_str(), label.size());

  FILL_ATTR(keyTemplate[5], CKA_MODULUS, (void*) key.modulus.c_str(), key.modulus.size());
  FILL_ATTR(keyTemplate[6], CKA_PUBLIC_EXPONENT, (void*) key.publicExponent.c_str(), key.publicExponent.size());
  FILL_ATTR(keyTemplate[7], CKA_PRIVATE_EXPONENT, (void*) key.privateExponent.c_str(), key.privateExponent.size());
  FILL_ATTR(keyTemplate[8], CKA_PRIME_1, (void*) key.p.c_str(), key.p.size());
  FILL_ATTR(keyTemplate[9], CKA_PRIME_2, (void*) key.q.c_str(), key.q.size());
  FILL_ATTR(keyTemplate[10], CKA_EXPONENT_1, (void*) key.dmp1.c_str(), key.dmp1.size());
  FILL_ATTR(keyTemplate[11], CKA_EXPONENT_2, (void*) key.dmq1.c_str(), key.dmq1.size());
  FILL_ATTR(keyTemplate[12], CKA_COEFFICIENT, (void*) key.iqmp.c_str(), key.iqmp.size());
  if (usage == USAGE_SIGNATURE)
    {
      FILL_ATTR(keyTemplate[13], CKA_SIGN, &_true, sizeof(CK_BBOOL));
      FILL_ATTR(keyTemplate[14], CKA_SIGN_RECOVER, &_false, sizeof(CK_BBOOL));
      FILL_ATTR(keyTemplate[15], CKA_DECRYPT, &_false, sizeof(CK_BBOOL));
    }
  else if (usage == USAGE_ENCRYPTION)
    {
      FILL_ATTR(keyTemplate[13], CKA_SIGN, &_false, sizeof(CK_BBOOL));
      FILL_ATTR(keyTemplate[14], CKA_SIGN_RECOVER, &_false, sizeof(CK_BBOOL));
      FILL_ATTR(keyTemplate[15], CKA_DECRYPT, &_true, sizeof(CK_BBOOL));
    }
  else
    {
      throw P11Exception(CKR_TEMPLATE_INCONSISTENT, "WriteRSAPrivateKey");
    }
  FILL_ATTR(keyTemplate[16], CKA_MODIFIABLE, &_false, sizeof(CK_BBOOL));
  FILL_ATTR(keyTemplate[17], CKA_SENSITIVE, &_true, sizeof(CK_BBOOL));
  FILL_ATTR(keyTemplate[18], CKA_EXTRACTABLE, &_false, sizeof(CK_BBOOL));
  FILL_ATTR(keyTemplate[19], CKA_PRIVATE, &_true, sizeof(CK_BBOOL));
  
  rv = p11->C_CreateObject(hSession, (CK_ATTRIBUTE*)&keyTemplate, 20, &h);
  if (rv != CKR_OK)
    throw P11Exception(rv, "C_CreateObject");
  // Clé publique
  FILL_ATTR(keyTemplate[0], CKA_TOKEN, &_true, sizeof(_true));
  FILL_ATTR(keyTemplate[1], CKA_CLASS, &pubObjectClass, sizeof(pubObjectClass));
  FILL_ATTR(keyTemplate[2], CKA_KEY_TYPE, &keyType, sizeof(keyType));
  FILL_ATTR(keyTemplate[3], CKA_ID, (void*)&id, sizeof(unsigned int));
  FILL_ATTR(keyTemplate[4], CKA_LABEL, (void*)label.c_str(), label.size());

  FILL_ATTR(keyTemplate[5], CKA_MODULUS, (void*) key.modulus.c_str(), key.modulus.size());
  FILL_ATTR(keyTemplate[6], CKA_PUBLIC_EXPONENT, (void*) key.publicExponent.c_str(), key.publicExponent.size());
  if (usage == USAGE_SIGNATURE)
    {
      FILL_ATTR(keyTemplate[7], CKA_VERIFY, &_true, sizeof(CK_BBOOL));
      FILL_ATTR(keyTemplate[8], CKA_VERIFY_RECOVER, &_false, sizeof(CK_BBOOL));
      FILL_ATTR(keyTemplate[9], CKA_ENCRYPT, &_false, sizeof(CK_BBOOL));
    }
  else if (usage == USAGE_ENCRYPTION)
    {
      FILL_ATTR(keyTemplate[7], CKA_VERIFY, &_false, sizeof(CK_BBOOL));  
      FILL_ATTR(keyTemplate[8], CKA_VERIFY_RECOVER, &_false, sizeof(CK_BBOOL));
      FILL_ATTR(keyTemplate[9], CKA_ENCRYPT, &_true, sizeof(CK_BBOOL));
    }
  else
    {
      throw P11Exception(CKR_TEMPLATE_INCONSISTENT, "WriteRSAPrivateKey");
    }
  FILL_ATTR(keyTemplate[10], CKA_MODIFIABLE, &_false, sizeof(CK_BBOOL));
  FILL_ATTR(keyTemplate[11], CKA_PRIVATE, &_false, sizeof(CK_BBOOL));

  rv = p11->C_CreateObject(hSession, (CK_ATTRIBUTE*)&keyTemplate, 12, &h);
  if (rv != CKR_OK)
    throw P11Exception(rv, "C_CreateObject");
}

std::string
P11Helper::wrap(CK_OBJECT_HANDLE hKeyToWrap,
        CK_OBJECT_HANDLE  hWrappingKey,
        CK_MECHANISM_TYPE  mechanism,
        const std::string&  iv)
{
  CK_RV        rv;

  // First we check the object to wrap
  CK_KEY_TYPE  key_type = getAttr<CK_KEY_TYPE> (CKA_KEY_TYPE, hKeyToWrap);
  (void)key_type;
  CK_OBJECT_CLASS clazz = getAttr<CK_OBJECT_CLASS> (CKA_CLASS, hKeyToWrap);
  if (clazz != CKO_PRIVATE_KEY)
    throw std::invalid_argument("P11Helper::extractWrappedPrivateKey : object key type invalid");

  // Private Key Wrapping
  CK_MECHANISM  ck_mech = { mechanism, (void*)iv.c_str(), iv.length() };
  // CK_MECHANISM  ck_mech = { mechanism, NULL, 0 };
  CK_BYTE wrappedKey[5000];
  CK_ULONG ulWrappedKeyLen = 5000;

  rv = p11->C_WrapKey(hSession, &ck_mech,
            hWrappingKey, hKeyToWrap,
            wrappedKey, &ulWrappedKeyLen);

  if (rv != CKR_OK)
    throw P11Exception(rv, "C_WrapKey");

  return std::string((char*)wrappedKey, ulWrappedKeyLen);
}

std::string
P11Helper::extractCertificate(CK_OBJECT_HANDLE obj)
{
  CK_OBJECT_CLASS clazz = 0;
  CK_ULONG len = 0;
  char *value = NULL;

  clazz = getAttr<CK_OBJECT_CLASS> (CKA_CLASS, obj);

  if (clazz != CKO_CERTIFICATE)
    throw std::invalid_argument("P11Helper::extractCertificate : object key type invalid");
  getAttr<char>(CKA_VALUE, obj, value, len);
  std::string res (value, len);
  free(value);
  value = NULL;
  return res;
}

#if 0
std::string
P11Helper::sign(const std::string& data,
          CK_MECHANISM_TYPE mechanism,
        CK_OBJECT_HANDLE hKey)
{
  CK_RV      rv;
  CK_MECHANISM  ck_mech = { mechanism, NULL, 0 };
  CK_BYTE     sig[1024];
  CK_ULONG    sigLen;

  // FIXME Static signature length. Need to be calculated.
  sigLen = sizeof(sig);
  rv = p11->C_SignInit(hSession, &ck_mech, hKey);
  if (rv != CKR_OK)
    throw P11Exception(rv, "C_SignInit");

  // We use the three steps (C_SignInit, C_SignUpdate, C_SignFinal)
  // because SoftHSM does not support calling directly C_Sign.
  rv = p11->C_SignUpdate(hSession, (unsigned char*)data.c_str(),
               data.size());
  if (rv != CKR_OK)
    throw P11Exception(rv, "C_SignUpdate");

  rv = p11->C_SignFinal(hSession, sig, &sigLen);
  if (rv != CKR_OK)
    throw P11Exception(rv, "C_SignFinal");
  //FIXME ulong -> uint
  std::string res ((const char*)sig, (unsigned int)sigLen);

  return res;

  // FIXME We might want to verify the signature size.
  // Idea from pkcs11-tool source code.
}
#endif


std::string
P11Helper::sign(const std::string& data,
                CK_MECHANISM_TYPE mechanism,
                CK_OBJECT_HANDLE hKey)
{
  CK_RV      rv;
  CK_MECHANISM  ck_mech = { mechanism, NULL, 0 };
  CK_BYTE     sig[1024];
  CK_ULONG    sigLen;

  // FIXME Static signature length. Need to be calculated.
  sigLen = sizeof(sig);
  rv = p11->C_SignInit(hSession, &ck_mech, hKey);
  if (rv != CKR_OK)
    throw P11Exception(rv, "C_SignInit");

  // We use the three steps (C_SignInit, C_SignUpdate, C_SignFinal)
  // because SoftHSM does not support calling directly C_Sign.
  rv = p11->C_Sign(hSession, (unsigned char*)data.c_str(),
               data.size(), sig, &sigLen);
  if (rv != CKR_OK)
    throw P11Exception(rv, "C_Sign");

  //FIXME ulong -> uint
  std::string res ((const char*)sig, (unsigned int)sigLen);

  return res;

  // FIXME We might want to verify the signature size.
  // Idea from pkcs11-tool source code.
}


static const char *p11_utf8_to_local(CK_UTF8CHAR *string,
                   size_t      len)
{
  static char  buffer[512];
  size_t    n, m;

  while (len && string[len-1] == ' ')
    len--;

  /* For now, simply copy this thing */
  for (n = m = 0; n < sizeof(buffer) - 1; n++) {
    if (m >= len)
      break;
    buffer[n] = string[m++];
  }
  buffer[n] = '\0';
  return buffer;
}
