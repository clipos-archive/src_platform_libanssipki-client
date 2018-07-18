// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2013-2018 ANSSI. All Rights Reserved.
#include <stdexcept>
#include <openssl/x509.h>

#include "pkcs11/p11-helper.h"
#include "utils.h"

__attribute__((constructor))
static void  init_ossl() {
  OpenSSL_add_all_algorithms();
}

namespace LIBANSSIPKI
{

KeyUsage_e keyUsageFromStr(const std::string& str) {
  if (str == "DigitalSignature")
    return DigitalSignature;
  if (str == "NonRepudiation")
    return NonRepudiation;
  if (str == "KeyEncipherment")
    return KeyEncipherment;
  if (str == "DataEncipherment")
    return DataEncipherment;
  if (str == "KeyAgreement")
    return KeyAgreement;
  if (str == "KeyCertSign")
    return KeyCertSign;
  if (str == "CRLSign")
    return CRLSign;
  if (str == "EncipherOnly")
    return EncipherOnly;
  if (str == "DecipherOnly")
    return DecipherOnly;
  throw std::invalid_argument("Invalid keyUsage string");
}

ExtendedKeyUsage_e extendedKeyUsageFromStr(const std::string& str) {
  if (str == "ServerAuth")
    return ServerAuth;
  if (str == "ClientAuth")
    return ClientAuth;
  if (str == "CodeSigning")
    return CodeSigning;
  if (str == "EmailProtection")
    return EmailProtection;
  if (str == "IPSecEndSystem")
    return IPSecEndSystem;
  if (str == "IPSecTunnel")
    return IPSecTunnel;
  if (str == "IPSecUser")
    return IPSecUser;
  if (str == "TimeStamping")
    return TimeStamping;
  if (str == "OCSPSigning")
    return OCSPSigning;
  throw std::invalid_argument("Invalid keyUsage string");
}

SAN_e SANFromStr(const std::string& str) {
  if (str == "email")
    return SAN_Email;
  if (str == "uri")
    return SAN_URI;
  if (str == "ip")
    return SAN_IPAddress;
  if (str == "dns")
    return SAN_DNS;
  throw std::invalid_argument("Invalid keyUsage string");
}

std::string
bio2string(BIO* b)
{
  std::string buf;
  while(1) {
    std::string block(1024, 0);
    int ret = BIO_read(b, (char*)(block.c_str()), block.size());
    if(ret <= 0)
      break;
    block.resize(ret);
    buf.append(block);
    if(ret != 1024)
      break;
  }
  BIO_free(b);
  return buf;
}

BIO*
string2bio(const std::string& content)
{
  BIO* b = BIO_new_mem_buf((void*)content.c_str(), content.length());
  return b;
}

X509* DERtoX509 (std::string der) {
  BIO*      bi = NULL;
  X509*       x = NULL;

  bi = BIO_new(BIO_s_mem());
  BIO_write(bi, der.c_str(), der.size());
  x = d2i_X509_bio(bi, NULL);
  BIO_free(bi);
  return x;
}

std::string
generateSerialNumber() {
  // 20 bits serial
  // 4 bits of serialNumberCount
  // 16 bits of alea
  std::string str;

  str.resize(20);
  P11Helper::getInstance()->generateRandom((unsigned char*)(str.c_str()), 20);

  // RFC 5280 : The serial number MUST be a positive integer.
  str[0] = str[0] & 0x7;

  return str;
}

std::string
generateSerialNumberWithCounter(unsigned long serialNumberCount) {
  // 20 bits serial
  // 4 bits of serialNumberCount
  // 16 bits of alea
  serial_u serial;
  std::string str;

  serial.count = serialNumberCount;

  P11Helper::getInstance()->generateRandom((unsigned char*)(serial.str) + 4, 16);
  str = std::string (serial.str, 20);

  return str;
}

}
