// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2013-2018 ANSSI. All Rights Reserved.
#ifndef X509CRL_H_
# define X509CRL_H_

# include "x509cert.h"

namespace LIBANSSIPKI
{
class X509Crl
{
public:
  /**
   *  @function X509Crl
   *  @brief    Constructeur: Creation d'une CRL vide pour une AC.
   *  @param    issuer  AC
   *  @param    nextuUpdateNbDays Nombre de jours avant la prochaine CRL
   *  @param    signAlgorithmNID  NID de l'algorithme de signature a utiliser.
   */
  X509Crl(const X509Cert* issuer,
          unsigned int    nextUpdateNbDays,
          unsigned long   signAlgorithmNID);

  /**
   *  @function ~X509Crl
   *  @brief    Destructeur: Detruit la CRL
   */
  ~X509Crl();

  /**
   *  @function addRevokedCertificate
   *  @brief    Ajoute un certificat revoque
   *  @param    serialNumber    Numero de serie du certificat revoque
   *  @param    revocationTime  Date de la revocation
   */
  void addRevokedCertificate(const std::string& serialNumber,
                             const std::string& revocationTime);

  /**
   *  @function setSignature
   *  @brief    Ajout de la signature de la CRL.
   */
  void setSignature(const std::string& signature);

  /**
   *  @function getLastUpdate
   *  @brief    retourne la date de creation de la CRL
   */
  std::string getLastUpdate() const;

  /**
   *  @function dump
   *  @brief    retourne une description textuelle de la CRL
   */
  std::string dump() const;

  /**
   *  @function toTbsDER
   *  @brief    retourne le bloc TBS de la CRL pour la signature
   */
  std::string toTbsDER() const;

  /**
   *  @function toDER
   *  @brief    retourne la CRL signee au format DER
   */
  std::string toDER() const ;

protected:
  /* Pointeur vers le certificat issuer.*/
  const X509Cert*    issuer;

  /* Representation de la crl au format OpenSSL */
  X509_CRL*      osslX509_CRL;

};
} // namespace LIBANSSIPKI

#endif /* X509CRL_H_ */
