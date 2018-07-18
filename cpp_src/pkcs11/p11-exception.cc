// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2013-2018 ANSSI. All Rights Reserved.
#include <sstream>

#include "pkcs11/pkcs11.h"
#include "pkcs11/p11-exception.h"

using namespace LIBANSSIPKI;

static const std::string CKR2Str(CK_ULONG res);
static const std::string CKA2Str(CK_ULONG res);

P11Exception::P11Exception(const unsigned int rv, const std::string& functionName, unsigned int ckaParam)
{
  std::stringstream ss;

  ss << functionName + "(" + std::string(CKA2Str(ckaParam))  + ")"
     << " failed: rv = " << CKR2Str(rv) << "(0x" << std::hex <<  rv << ")" << std::endl;
  _details = ss.str();
}

P11Exception::P11Exception (const unsigned int rv, const std::string& details) :
  _rv(rv)
{
  std::stringstream ss;

  ss << details << " failed: rv = " << CKR2Str(rv) << "(0x" << std::hex <<  rv << ")" << std::endl;
  _details = ss.str();
}



static const std::string CKA2Str(CK_ULONG res)
{
  switch (res) {
    case CKA_CLASS: return "CKA_CLASS";
    case CKA_TOKEN: return "CKA_TOKEN";
    case CKA_PRIVATE: return "CKA_PRIVATE";
    case CKA_LABEL: return "CKA_LABEL";
    case CKA_APPLICATION: return "CKA_APPLICATION";
    case CKA_VALUE: return "CKA_VALUE";
    case CKA_OBJECT_ID: return "CKA_OBJECT_ID";
    case CKA_CERTIFICATE_TYPE: return "CKA_CERTIFICATE_TYPE";
    case CKA_ISSUER: return "CKA_ISSUER";
    case CKA_SERIAL_NUMBER: return "CKA_SERIAL_NUMBER";
    case CKA_AC_ISSUER: return "CKA_AC_ISSUER";
    case CKA_OWNER: return "CKA_OWNER";
    case CKA_ATTR_TYPES: return "CKA_ATTR_TYPES";
    case CKA_TRUSTED: return "CKA_TRUSTED";
    case CKA_CERTIFICATE_CATEGORY: return "CKA_CERTIFICATE_CATEGORY";
    case CKA_JAVA_MIDP_SECURITY_DOMAIN: return "CKA_JAVA_MIDP_SECURITY_DOMAIN";
    case CKA_URL: return "CKA_URL";
    case CKA_HASH_OF_SUBJECT_PUBLIC_KEY: return "CKA_HASH_OF_SUBJECT_PUBLIC_KEY";
    case CKA_HASH_OF_ISSUER_PUBLIC_KEY: return "CKA_HASH_OF_ISSUER_PUBLIC_KEY";
    case CKA_CHECK_VALUE: return "CKA_CHECK_VALUE";
    case CKA_KEY_TYPE: return "CKA_KEY_TYPE";
    case CKA_SUBJECT: return "CKA_SUBJECT";
    case CKA_ID: return "CKA_ID";
    case CKA_SENSITIVE: return "CKA_SENSITIVE";
    case CKA_ENCRYPT: return "CKA_ENCRYPT";
    case CKA_DECRYPT: return "CKA_DECRYPT";
    case CKA_WRAP: return "CKA_WRAP";
    case CKA_UNWRAP: return "CKA_UNWRAP";
    case CKA_SIGN: return "CKA_SIGN";
    case CKA_SIGN_RECOVER: return "CKA_SIGN_RECOVER";
    case CKA_VERIFY: return "CKA_VERIFY";
    case CKA_VERIFY_RECOVER: return "CKA_VERIFY_RECOVER";
    case CKA_DERIVE: return "CKA_DERIVE";
    case CKA_START_DATE: return "CKA_START_DATE";
    case CKA_END_DATE: return "CKA_END_DATE";
    case CKA_MODULUS: return "CKA_MODULUS";
    case CKA_MODULUS_BITS: return "CKA_MODULUS_BITS";
    case CKA_PUBLIC_EXPONENT: return "CKA_PUBLIC_EXPONENT";
    case CKA_PRIVATE_EXPONENT: return "CKA_PRIVATE_EXPONENT";
    case CKA_PRIME_1: return "CKA_PRIME_1";
    case CKA_PRIME_2: return "CKA_PRIME_2";
    case CKA_EXPONENT_1: return "CKA_EXPONENT_1";
    case CKA_EXPONENT_2: return "CKA_EXPONENT_2";
    case CKA_COEFFICIENT: return "CKA_COEFFICIENT";
    case CKA_PRIME: return "CKA_PRIME";
    case CKA_SUBPRIME: return "CKA_SUBPRIME";
    case CKA_BASE: return "CKA_BASE";
    case CKA_PRIME_BITS: return "CKA_PRIME_BITS";
    case CKA_SUB_PRIME_BITS: return "CKA_SUB_PRIME_BITS";
    case CKA_VALUE_BITS: return "CKA_VALUE_BITS";
    case CKA_VALUE_LEN: return "CKA_VALUE_LEN";
    case CKA_EXTRACTABLE: return "CKA_EXTRACTABLE";
    case CKA_LOCAL: return "CKA_LOCAL";
    case CKA_NEVER_EXTRACTABLE: return "CKA_NEVER_EXTRACTABLE";
    case CKA_ALWAYS_SENSITIVE: return "CKA_ALWAYS_SENSITIVE";
    case CKA_KEY_GEN_MECHANISM: return "CKA_KEY_GEN_MECHANISM";
    case CKA_MODIFIABLE: return "CKA_MODIFIABLE";
    case CKA_ECDSA_PARAMS: return "CKA_ECDSA_PARAMS";
    //case CKA_EC_PARAMS: return "CKA_EC_PARAMS";
    case CKA_EC_POINT: return "CKA_EC_POINT";
    case CKA_SECONDARY_AUTH: return "CKA_SECONDARY_AUTH";
    case CKA_AUTH_PIN_FLAGS: return "CKA_AUTH_PIN_FLAGS";
    case CKA_ALWAYS_AUTHENTICATE: return "CKA_ALWAYS_AUTHENTICATE";
    case CKA_WRAP_WITH_TRUSTED: return "CKA_WRAP_WITH_TRUSTED";
    case CKA_GOSTR3410_PARAMS: return "CKA_GOSTR3410_PARAMS";
    case CKA_GOSTR3411_PARAMS: return "CKA_GOSTR3411_PARAMS";
    case CKA_GOST28147_PARAMS: return "CKA_GOST28147_PARAMS";
    case CKA_HW_FEATURE_TYPE: return "CKA_HW_FEATURE_TYPE";
    case CKA_RESET_ON_INIT: return "CKA_RESET_ON_INIT";
    case CKA_HAS_RESET: return "CKA_HAS_RESET";
    case CKA_PIXEL_X: return "CKA_PIXEL_X";
    case CKA_PIXEL_Y: return "CKA_PIXEL_Y";
    case CKA_RESOLUTION: return "CKA_RESOLUTION";
    case CKA_CHAR_ROWS: return "CKA_CHAR_ROWS";
    case CKA_CHAR_COLUMNS: return "CKA_CHAR_COLUMNS";
    case CKA_COLOR: return "CKA_COLOR";
    case CKA_BITS_PER_PIXEL: return "CKA_BITS_PER_PIXEL";
    case CKA_CHAR_SETS: return "CKA_CHAR_SETS";
    case CKA_ENCODING_METHODS: return "CKA_ENCODING_METHODS";
    case CKA_MIME_TYPES: return "CKA_MIME_TYPES";
    case CKA_MECHANISM_TYPE: return "CKA_MECHANISM_TYPE";
    case CKA_REQUIRED_CMS_ATTRIBUTES: return "CKA_REQUIRED_CMS_ATTRIBUTES";
    case CKA_DEFAULT_CMS_ATTRIBUTES: return "CKA_DEFAULT_CMS_ATTRIBUTES";
    case CKA_SUPPORTED_CMS_ATTRIBUTES: return "CKA_SUPPORTED_CMS_ATTRIBUTES";
    case CKA_WRAP_TEMPLATE: return "CKA_WRAP_TEMPLATE";
    case CKA_UNWRAP_TEMPLATE: return "CKA_UNWRAP_TEMPLATE";
    case CKA_ALLOWED_MECHANISMS: return "CKA_ALLOWED_MECHANISMS";
    case CKA_VENDOR_DEFINED: return "CKA_VENDOR_DEFINED";
    default:  return "unknown PKCS11 error";
  }
}

static const std::string CKR2Str(CK_ULONG res)
{
  switch (res) {
  case CKR_OK: return "CKR_OK";
  case CKR_CANCEL: return "CKR_CANCEL";
  case CKR_HOST_MEMORY: return "CKR_HOST_MEMORY";
  case CKR_SLOT_ID_INVALID: return "CKR_SLOT_ID_INVALID";
  case CKR_GENERAL_ERROR: return "CKR_GENERAL_ERROR";
  case CKR_FUNCTION_FAILED: return "CKR_FUNCTION_FAILED";
  case CKR_ARGUMENTS_BAD: return "CKR_ARGUMENTS_BAD";
  case CKR_NO_EVENT: return "CKR_NO_EVENT";
  case CKR_NEED_TO_CREATE_THREADS: return "CKR_NEED_TO_CREATE_THREADS";
  case CKR_CANT_LOCK: return "CKR_CANT_LOCK";
  case CKR_ATTRIBUTE_READ_ONLY: return "CKR_ATTRIBUTE_READ_ONLY";
  case CKR_ATTRIBUTE_SENSITIVE: return "CKR_ATTRIBUTE_SENSITIVE";
  case CKR_ATTRIBUTE_TYPE_INVALID: return "CKR_ATTRIBUTE_TYPE_INVALID";
  case CKR_ATTRIBUTE_VALUE_INVALID: return "CKR_ATTRIBUTE_VALUE_INVALID";
  case CKR_DATA_INVALID: return "CKR_DATA_INVALID";
  case CKR_DATA_LEN_RANGE: return "CKR_DATA_LEN_RANGE";
  case CKR_DEVICE_ERROR: return "CKR_DEVICE_ERROR";
  case CKR_DEVICE_MEMORY: return "CKR_DEVICE_MEMORY";
  case CKR_DEVICE_REMOVED: return "CKR_DEVICE_REMOVED";
  case CKR_ENCRYPTED_DATA_INVALID: return "CKR_ENCRYPTED_DATA_INVALID";
  case CKR_ENCRYPTED_DATA_LEN_RANGE: return "CKR_ENCRYPTED_DATA_LEN_RANGE";
  case CKR_FUNCTION_CANCELED: return "CKR_FUNCTION_CANCELED";
  case CKR_FUNCTION_NOT_PARALLEL: return "CKR_FUNCTION_NOT_PARALLEL";
  case CKR_FUNCTION_NOT_SUPPORTED: return "CKR_FUNCTION_NOT_SUPPORTED";
  case CKR_KEY_HANDLE_INVALID: return "CKR_KEY_HANDLE_INVALID";
  case CKR_KEY_SIZE_RANGE: return "CKR_KEY_SIZE_RANGE";
  case CKR_KEY_TYPE_INCONSISTENT: return "CKR_KEY_TYPE_INCONSISTENT";
  case CKR_KEY_NOT_NEEDED: return "CKR_KEY_NOT_NEEDED";
  case CKR_KEY_CHANGED: return "CKR_KEY_CHANGED";
  case CKR_KEY_NEEDED: return "CKR_KEY_NEEDED";
  case CKR_KEY_INDIGESTIBLE: return "CKR_KEY_INDIGESTIBLE";
  case CKR_KEY_FUNCTION_NOT_PERMITTED: return "CKR_KEY_FUNCTION_NOT_PERMITTED";
  case CKR_KEY_NOT_WRAPPABLE: return "CKR_KEY_NOT_WRAPPABLE";
  case CKR_KEY_UNEXTRACTABLE: return "CKR_KEY_UNEXTRACTABLE";
  case CKR_MECHANISM_INVALID: return "CKR_MECHANISM_INVALID";
  case CKR_MECHANISM_PARAM_INVALID: return "CKR_MECHANISM_PARAM_INVALID";
  case CKR_OBJECT_HANDLE_INVALID: return "CKR_OBJECT_HANDLE_INVALID";
  case CKR_OPERATION_ACTIVE: return "CKR_OPERATION_ACTIVE";
  case CKR_OPERATION_NOT_INITIALIZED: return "CKR_OPERATION_NOT_INITIALIZED";
  case CKR_PIN_INCORRECT: return "CKR_PIN_INCORRECT";
  case CKR_PIN_INVALID: return "CKR_PIN_INVALID";
  case CKR_PIN_LEN_RANGE: return "CKR_PIN_LEN_RANGE";
  case CKR_PIN_EXPIRED: return "CKR_PIN_EXPIRED";
  case CKR_PIN_LOCKED: return "CKR_PIN_LOCKED";
  case CKR_SESSION_CLOSED: return "CKR_SESSION_CLOSED";
  case CKR_SESSION_COUNT: return "CKR_SESSION_COUNT";
  case CKR_SESSION_HANDLE_INVALID: return "CKR_SESSION_HANDLE_INVALID";
  case CKR_SESSION_PARALLEL_NOT_SUPPORTED: return "CKR_SESSION_PARALLEL_NOT_SUPPORTED";
  case CKR_SESSION_READ_ONLY: return "CKR_SESSION_READ_ONLY";
  case CKR_SESSION_EXISTS: return "CKR_SESSION_EXISTS";
  case CKR_SESSION_READ_ONLY_EXISTS: return "CKR_SESSION_READ_ONLY_EXISTS";
  case CKR_SESSION_READ_WRITE_SO_EXISTS: return "CKR_SESSION_READ_WRITE_SO_EXISTS";
  case CKR_SIGNATURE_INVALID: return "CKR_SIGNATURE_INVALID";
  case CKR_SIGNATURE_LEN_RANGE: return "CKR_SIGNATURE_LEN_RANGE";
  case CKR_TEMPLATE_INCOMPLETE: return "CKR_TEMPLATE_INCOMPLETE";
  case CKR_TEMPLATE_INCONSISTENT: return "CKR_TEMPLATE_INCONSISTENT";
  case CKR_TOKEN_NOT_PRESENT: return "CKR_TOKEN_NOT_PRESENT";
  case CKR_TOKEN_NOT_RECOGNIZED: return "CKR_TOKEN_NOT_RECOGNIZED";
  case CKR_TOKEN_WRITE_PROTECTED: return "CKR_TOKEN_WRITE_PROTECTED";
  case CKR_UNWRAPPING_KEY_HANDLE_INVALID: return "CKR_UNWRAPPING_KEY_HANDLE_INVALID";
  case CKR_UNWRAPPING_KEY_SIZE_RANGE: return "CKR_UNWRAPPING_KEY_SIZE_RANGE";
  case CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT: return "CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT";
  case CKR_USER_ALREADY_LOGGED_IN: return "CKR_USER_ALREADY_LOGGED_IN";
  case CKR_USER_NOT_LOGGED_IN: return "CKR_USER_NOT_LOGGED_IN";
  case CKR_USER_PIN_NOT_INITIALIZED: return "CKR_USER_PIN_NOT_INITIALIZED";
  case CKR_USER_TYPE_INVALID: return "CKR_USER_TYPE_INVALID";
  case CKR_USER_ANOTHER_ALREADY_LOGGED_IN: return "CKR_USER_ANOTHER_ALREADY_LOGGED_IN";
  case CKR_USER_TOO_MANY_TYPES: return "CKR_USER_TOO_MANY_TYPES";
  case CKR_WRAPPED_KEY_INVALID: return "CKR_WRAPPED_KEY_INVALID";
  case CKR_WRAPPED_KEY_LEN_RANGE: return "CKR_WRAPPED_KEY_LEN_RANGE";
  case CKR_WRAPPING_KEY_HANDLE_INVALID: return "CKR_WRAPPING_KEY_HANDLE_INVALID";
  case CKR_WRAPPING_KEY_SIZE_RANGE: return "CKR_WRAPPING_KEY_SIZE_RANGE";
  case CKR_WRAPPING_KEY_TYPE_INCONSISTENT: return "CKR_WRAPPING_KEY_TYPE_INCONSISTENT";
  case CKR_RANDOM_SEED_NOT_SUPPORTED: return "CKR_RANDOM_SEED_NOT_SUPPORTED";
  case CKR_RANDOM_NO_RNG: return "CKR_RANDOM_NO_RNG";
  case CKR_DOMAIN_PARAMS_INVALID: return "CKR_DOMAIN_PARAMS_INVALID";
  case CKR_BUFFER_TOO_SMALL: return "CKR_BUFFER_TOO_SMALL";
  case CKR_SAVED_STATE_INVALID: return "CKR_SAVED_STATE_INVALID";
  case CKR_INFORMATION_SENSITIVE: return "CKR_INFORMATION_SENSITIVE";
  case CKR_STATE_UNSAVEABLE: return "CKR_STATE_UNSAVEABLE";
  case CKR_CRYPTOKI_NOT_INITIALIZED: return "CKR_CRYPTOKI_NOT_INITIALIZED";
  case CKR_CRYPTOKI_ALREADY_INITIALIZED: return "CKR_CRYPTOKI_ALREADY_INITIALIZED";
  case CKR_MUTEX_BAD: return "CKR_MUTEX_BAD";
  case CKR_MUTEX_NOT_LOCKED: return "CKR_MUTEX_NOT_LOCKED";
  case CKR_VENDOR_DEFINED: return "CKR_VENDOR_DEFINED";
  }
  return "unknown PKCS11 error";
}
