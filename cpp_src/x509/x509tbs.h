// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2013-2018 ANSSI. All Rights Reserved.
#ifndef X509TBS_H_
# define X509TBS_H_

# include "x509/x509req.h"

namespace LIBANSSIPKI
{
/**
 * @class X509Tbs
 * @brief X509Tbs represente un certificat avant signature.
 *         toutes les informations d'un certificat sont présentes.
 *        Un X509Tbs peut être obtenu depuis un X509Req via la méthode
 *        X509Tbs::FromX509Req où via une renouvellement de certificat via
 *        la méthode X509Cert::renew
 */
class X509Tbs : public X509Req
{
public:
  /**
   * @function FromX509Req
   * @brief Transforme une requête X509Req en X509Tbs prêt à être signé.
   *      Le pointeur req est casté dynamiquement en X509Tbs et est retourné.
   *      Celui-ci ne doit plus être utilisé par la suite.
   *
   * @param req X509 La requête de certification.
   * @param notBefore Début de validité du certificat.
   * @param notAfter Fin de validité du certificat
   * @param signAlgorithm Algorithme à utiliser pour la signature.
   * @param serialNumber Numéro de série du certificat.
   * @param issuerDN Pointeur vers le certificat issuer.
   *      (NULL le certificat doit être auto-signé.)
   */
  static X509Tbs* FromX509Req(X509Req*        req,
                const std::string&    notBefore,
                const std::string&    notAfter,
                unsigned long      signAlgorithmNID,
                const std::string&    serialNumber,
                const X509Cert*      issuer);

protected:
  /**
   * @function X509Tbs
   * @brief Construit un object X509Tbs vide.
   *     Important : Ce constructeur ne doit jamais être appelé explicitement.
   *    Il est appellé uniquement au moment de la création d'un X509Cert.
   */
  X509Tbs();

  /**
   * @function ~X509Cert
   * @brief Destructeur. Détruit la clé privée et l'object X509 OpenSSL
   */
  virtual ~X509Tbs();
public:
  /**
   * @function getSignAlgoNID
   * @brief retourne l'algorithme de signature
   */
  unsigned long    getSignAlgoNID() const;

  /**
   * @function getIssuerDNString
   * @brief retourne le champs issuer sous forme textuelle.
   *      (Si certificat autosigné, le la valeur textuelle du
   *       champs subject est retournée)
   */
  std::string      getIssuerDNString() const;

  /**
   * @function getNotBefore
   * @brief retourne la date de debut de validité au format %y%m%d000000Z
   */
  const std::string&  getNotBefore() const;

  /**
   * @function getNotAfter
   * @brief retourne la date de fin de validité au format %y%m%d000000Z
   */
  const std::string&  getNotAfter() const;

  /**
   * @function getSerialNumber
   * @brief retourne le numero de série du certificat.
   */
  const std::string& getSerialNumber() const;

  /**
   * @function dump()
   * @brief    Retourne une représentation textuelle et lisible de la requête de certification.
   */
  std::string      dump() const;

  /**
   * @function toDER()
   * @brief    Retourne le bloc TBS à signer.
   */
  std::string      toDER() const;

private:
  /**
   * @function generateOSSLX509
   * @brief generateOSSLX509 est appelé lorsqu'un X509Tbs est crée à partir d'un X509Req.
   *      (Voir: X509Tbs::FromX509Req)
   *      A partir des attributs de l'object, un certificat OpenSSL sans signature (bloc TBS)
   *      est généré et enregistré dans l'attribut osslX509.
   */
  void generateOSSLX509();

protected:
  /** Certificate serial number */
  std::string      serialNumber;
  /** Algorith used to sign the certificate */
  unsigned long    signAlgorithmNID;

  /* validity */
  std::string      notBefore;
  std::string      notAfter;

  /* DN de l'issuer */
  X509Name      issuerDN;

  /* Pointeur vers le certificat issuer. NULL si certificat autosigné */
  const X509Cert*    issuer;

  /* Representation du certificat au format OpenSSL */
  X509*        osslX509;

};
} // namespace LIBANSSIPKI

#endif /* X509TBS_H_ */
