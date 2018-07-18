// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2013-2018 ANSSI. All Rights Reserved.
#include <assert.h>
// Includes for IP Subject alt names
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#include "x509req.h"
#include "x509cert.h"

using namespace LIBANSSIPKI;

LIBANSSIPKI::X509Req*
LIBANSSIPKI::newX509Request(const std::string &dn) {
  X509Cert* cert = new X509Cert();
  cert->subjectDN = X509Name(dn);
  return cert;
}

X509Req::X509Req() :
  subjectDN(""),
  isCAFlag(false),
  caPathLimit(0),
  publicKey(0) {
}

X509Req::~X509Req() {
  if (publicKey)
    delete publicKey;
}

std::string
X509Req::getSubjectDNString() const {
  return subjectDN.toString();
}

void
X509Req::setPublicKey(PublicKey* newPublicKey) {
  publicKey = newPublicKey;
}

void
X509Req::setCApathLimit(unsigned int caPathLimit) {
  // FIXME Check Maximum
  this->caPathLimit = caPathLimit;
}

void
X509Req::setCA() {
  this->isCAFlag = true;
}

bool
X509Req::isCA() const {
  return isCAFlag;
  // return (constraints.find(KeyCertificateSign) != constraints.end());
}

unsigned int
X509Req::getCAPathLimit() const {
  return caPathLimit;
}

void
X509Req::setKeyUsage (KeyUsage_e ku) {
  keyUsages.insert(ku);
}

void
X509Req::setExtendedKeyUsage (ExtendedKeyUsage_e eku) {
  extKeyUsages.insert(eku);
}

void
X509Req::addSubjectAltNameIP (const std::string& sanIP){
  SANs.push_back(std::pair<SAN_e, std::string> (SAN_IPAddress, sanIP));
}

void
X509Req::addSubjectAltNameDNS (const std::string& sanDNS){
  SANs.push_back(std::pair<SAN_e, std::string> (SAN_DNS, sanDNS));
}

void
X509Req::addSubjectAltNameEmail (const std::string& sanEmail){
  SANs.push_back(std::pair<SAN_e, std::string> (SAN_Email, sanEmail));
}

void
X509Req::addSubjectAltNameURI (const std::string& sanURI){
  SANs.push_back(std::pair<SAN_e, std::string> (SAN_URI, sanURI));
}

void
X509Req::addCertificatePolicy (const std::string& OID,
                 const std::string&  CPS) {
  policies.push_back(std::pair<std::string,std::string> (OID, CPS));
}

std::string
X509Req::getSubjectDNDER() const {
  return subjectDN.toDER();
}

void
X509Req::addOSSLextension(const std::string& content) {
  genericOSSLExtensions.push_back(content);
}
