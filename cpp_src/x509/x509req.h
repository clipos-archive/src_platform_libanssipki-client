// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2013-2018 ANSSI. All Rights Reserved.
#ifndef X509REQ_H_
# define X509REQ_H_

# include <set>
# include <string>
# include <openssl/x509.h>
# include <openssl/x509v3.h>

# include "x509/public-key.h"
# include "x509/x509name.h"

namespace LIBANSSIPKI
{
enum SAN_e {
  SAN_Email,
  SAN_URI,
  SAN_DNS,
  SAN_IPAddress
};

enum KeyUsage_e {
  DigitalSignature,
  NonRepudiation,
  KeyEncipherment,
  DataEncipherment,
  KeyAgreement,
  KeyCertSign,
  CRLSign,
  EncipherOnly,
  DecipherOnly,
};

enum ExtendedKeyUsage_e {
  ServerAuth,
  ClientAuth,
  CodeSigning,
  EmailProtection,
  IPSecEndSystem,
  IPSecTunnel,
  IPSecUser,
  TimeStamping,
  OCSPSigning,
};

enum ConstraintBit
{
  Bit_DigitalSignature   = 0,
  Bit_NonRepudiation     = 1,
  Bit_KeyEncipherment    = 2,
  Bit_DataEncipherment   = 3,
  Bit_KeyAgreement       = 4,
  Bit_KeyCertSign        = 5,
  Bit_CRLSign            = 6,
  Bit_EncipherOnly       = 7,
  Bit_DecipherOnly       = 8
};

class X509Cert;
class X509Tbs;
class X509Req;

/**
 * @function newX509Request
 * @brief Crée une nouvelle requête de certificat X509.
 *        (Un object X509Cert est créé pour être transformé
 *        via X509Tbs::FromX509Req et X509Cert::FromX509Tbs)
 * @throw std::invalid_argument Une exception est relevée si le DN est incorrecte
 *
 * @param subjectDN Sujet du certificat à créer.
 */
X509Req* newX509Request(const std::string &dn);

/**
 * @class X509Req
 * @brief X509Request (CSR) object
 */
class X509Req
{
protected:
  /**
   * @function X509Req
   * @brief Construit un object X509Req vide.
   *        Important : Ce constructeur ne doit jamais être appelé explicitement.
   *        Il est appellé uniquement via la fonction newX509Request.
   */
  X509Req();

public:
  /**
   * @function ~X509Req
   * @brief Destruction d'un object X509Req.
   */
  virtual ~X509Req();

  /**
   * @function setPublicKey
   * @brief Assigne le pointeur vers la clé publique.
   */
  void setPublicKey(PublicKey* newPublicKey);

  /**
   * @function setKeyUsage
   * @brief Ajoute un KeyUsage au set de KeyUsages
   *
   * @param value valeur du keyusage à ajouter (enum KeyUsage_e)
   */
  void setKeyUsage (KeyUsage_e ku);

  /**
   * @function setExtendedKeyUsage
   * @brief Ajoute un extended KeyUsage au set de extendedKeyUsages
   *
   * @param value valeur du extkeyusage à ajouter (enum ExtendedKeyUsage_e)
   */
  void setExtendedKeyUsage (ExtendedKeyUsage_e eku);

  /**
   * @function addSubjectAltNameIP
   * @brief Ajoute une IP aux subjectAltName
   */
  void addSubjectAltNameIP (const std::string& sanIP);

  /**
   * @function addSubjectAltNameDNS
   * @brief Ajoute un DNS aux subjectAltName
   */
  void addSubjectAltNameDNS (const std::string& sanDNS);

  /**
   * @function addSubjectAltNameEmail
   * @brief Ajoute une adresse email aux subjectAltName
   */
  void addSubjectAltNameEmail (const std::string& sanEmail);

  /**
   * @function addSubjectAltNameURI
   * @brief Ajoute une URI aux subjectAltName
   */
  void addSubjectAltNameURI (const std::string& sanURI);

  /**
   * @function addCertificatePolicy
   * @brief Ajoute une politique de certification.
   *
   * @param OID OID de la politique de certification utilisée
   * @param CPS URI vers le fichier décrivant les politiques de certifications.
   */
  void addCertificatePolicy (const std::string& OID, const std::string& CPS);

  /**
   * @function setCA
   * @brief Mets le flag CA à vrai
   *       (impacte la génération du bi-clé, le KeyUsage et le champs BasicConstraint)
   */
  void setCA();

  /**
   * @function setCApathLimit
   * @brief Assigne le maximum de liens dans la chaîne de certification, (0 = illimité)
   */
  void setCApathLimit(unsigned int caPathLimit);

  /**
   * @function parseOSSLextension
   * @brief Prends en paramètre le contenu de la section v3_extensions
   *       d'un fichier de configuration OpenSSL et ajoute les extensions
   *        générées à la CSR.
   */
  void addOSSLextension(const std::string& content);

  /**
   * @function getCApathLimit
   * @brief Retourne le maximum de liens dans la chaîne de certification, (0 = illimité)
   */
  unsigned int getCAPathLimit() const;

  /**
   * @function isCA
   * @brief Return vrai le certificat est un certificat d'AC.
   */
  bool isCA() const;

  /**
   * @function getSubjectDNString
   * @brief Retourne le sujet sous forme d'une chaîne de caractère.
   */
  std::string getSubjectDNString() const ;

  /**
   * @function getSubjectDNDER
   * @brief Retourne le sujet sous sa forme DER.
   */
  std::string getSubjectDNDER() const;

protected:
  /** subjectInfo : dn + subject alt name */
  X509Name      subjectDN;

  /** basic constraint CA Flag */
  bool        isCAFlag;

  /** cAPathLimit . */
  unsigned int    caPathLimit;

  /** key usage set  */
  std::set<KeyUsage_e>  keyUsages;

  /** extended key usage */
  std::set<ExtendedKeyUsage_e>  extKeyUsages;

  /** publicKey : certificate request public key */
  PublicKey*      publicKey;

  /** SANs : list of Subject Alternative name */
  std::list<std::pair<SAN_e, std::string> > SANs;

  /** policies : List of couple <OID,URI> */
  std::list<std::pair<std::string, std::string> > policies;

  std::list<std::string>  genericOSSLExtensions;

  friend  X509Req* newX509Request(const std::string &dn);
};
} // namespace LIBANSSIPKI

#endif /* X509REQ_H_ */
