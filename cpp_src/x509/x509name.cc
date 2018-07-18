// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2013-2018 ANSSI. All Rights Reserved.
#include <stdexcept>
#include <assert.h>
#include "x509name.h"

using namespace LIBANSSIPKI;

X509Name::X509Name(const std::string& dn) {
  if (dn != "")
    setDN(dn);
}


void
X509Name::setDN(const std::string& dn) {
  size_t startPos = 0;
  size_t equalPos = 0;
  size_t endPos = 0;
  std::string field;
  std::string value;

  if (dn == "")
    throw std::invalid_argument("Empty DN");

  do {
    equalPos = dn.find("=", startPos);
    endPos =  dn.find(",", equalPos);

    if (equalPos == std::string::npos)
      throw std::invalid_argument("Invalid DN Format");
    if ((endPos != std::string::npos) && (equalPos > endPos))
      throw std::invalid_argument("Invalid DN Format");


    field = dn.substr(startPos, equalPos - startPos);
    if (endPos == std::string::npos)
      value = dn.substr(equalPos + 1, dn.size() - (equalPos + 1));
    else
    {
      startPos =endPos + 1;
      value = dn.substr(equalPos + 1, endPos - (equalPos + 1));
    }
    if (value == "")
      throw std::invalid_argument("Invalid DN Format");
    if (field == "CN")
      addEntry(DN_CommonName, value);
    else if (field == "S")
      addEntry(DN_SurName, value);
    else if (field == "O")
      addEntry(DN_Organization, value);
    else if (field == "OU")
      addEntry(DN_OrganizationalUnit, value);
    else if (field == "C")
      addEntry(DN_Country, value);
    else if (field == "ST")
      addEntry(DN_State, value);
    else if (field == "L")
      addEntry(DN_Locality, value);
    else
      throw std::invalid_argument(std::string("Invalid DN Field \"") + field + "\"");

  } while (endPos != std::string::npos);
}

void
X509Name::addEntry(DN_e         type,
           const std::string&  value) {
  entries.push_back(std::pair<DN_e, std::string>(type, value));
}


std::string
X509Name::toString() const {
  std::string res = "";

  for (std::list<std::pair<DN_e, std::string> >::const_iterator it = entries.begin();
    it != entries.end(); ++it)
  {
    if (res != "")
      res += ",";
    switch (it->first) {
      case DN_CommonName:
        res += "CN="+it->second;
        break;
      case DN_SurName:
        res += "S="+it->second;
        break;
      case DN_Organization:
        res += "O="+it->second;
        break;
      case DN_OrganizationalUnit:
        res += "OU="+it->second;
        break;
      case DN_Country:
        res += "C="+it->second;
        break;
      case DN_State:
        res += "ST="+it->second;
        break;
      case DN_Locality:
        res += "L="+it->second;
        break;
    }
  }

  return res;
}

X509_NAME*
X509Name::toOSSLX509_NAME() const {
  X509_NAME*  name = 0;
  int      NID = 0;

  name = X509_NAME_new();
  for (std::list<std::pair<DN_e, std::string> >::const_iterator it = entries.begin();
    it != entries.end(); ++it)
  {
    switch (it->first) {
      case DN_CommonName:
        NID = NID_commonName;
        break;
      case DN_SurName:
        NID = NID_surname;
        break;
      case DN_Organization:
        NID = NID_organizationName;
        break;
      case DN_OrganizationalUnit:
        NID = NID_organizationalUnitName;
        break;
      case DN_Country:
        NID = NID_countryName;
        break;
      case DN_State:
        NID = NID_stateOrProvinceName;
        break;
      case DN_Locality:
        NID = NID_localityName;
        break;
      default:
        assert(0);
    }

    //FIXME toAscii , to Latin1 ? to Local8 ?
    // QByteArray ba = it->value().toAscii();
    X509_NAME_add_entry_by_NID(name, NID, MBSTRING_ASC, (unsigned char*)(it->second.c_str()), it->second.size(), -1, 0);
  }

  return name;
}

void
X509Name::fromOSSLX509_NAME(X509_NAME *name) {
  X509_NAME_ENTRY*  ne;
  ASN1_OBJECT*    obj;
  ASN1_STRING*    data;

  for (int i = 0; i < X509_NAME_entry_count(name); ++i) {
    ne = X509_NAME_get_entry(name, i);
    obj = X509_NAME_ENTRY_get_object(ne);
    data = X509_NAME_ENTRY_get_data(ne);

    if (OBJ_obj2nid(obj) == NID_commonName)
      addEntry(DN_CommonName, std::string((char*)(data->data), data->length));
    else if (OBJ_obj2nid(obj) == NID_surname)
      addEntry(DN_SurName, std::string((char*)(data->data), data->length));
    else if (OBJ_obj2nid(obj) == NID_countryName)
      addEntry(DN_Country, std::string((char*)(data->data), data->length));
    else if (OBJ_obj2nid(obj) == NID_localityName)
      addEntry(DN_Locality, std::string((char*)(data->data), data->length));
    else if (OBJ_obj2nid(obj) == NID_organizationName)
      addEntry(DN_Organization, std::string((char*)(data->data), data->length));
    else if (OBJ_obj2nid(obj) == NID_organizationalUnitName)
      addEntry(DN_OrganizationalUnit, std::string((char*)(data->data), data->length));
    else if (OBJ_obj2nid(obj) == NID_stateOrProvinceName)
      addEntry(DN_State, std::string((char*)(data->data), data->length));
    else
      //FIXME : OBJ not implemented
      throw (0);
  }
}

std::string
X509Name::toDER() const {
  unsigned char*  buf = 0;
  size_t  len;
  X509_NAME*  name = toOSSLX509_NAME();
  std::string res;

  len = i2d_X509_NAME(name, &buf);
  res = std::string((char*)buf, len);
  X509_NAME_free(name);
  free(buf);
  return res;
}
