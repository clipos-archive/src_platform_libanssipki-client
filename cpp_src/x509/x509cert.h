// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2013-2018 ANSSI. All Rights Reserved.
#ifndef X509CERT_H_
# define X509CERT_H_

# include "x509/x509tbs.h"
# include "utils.h"

namespace LIBANSSIPKI
{
/**
 * @class X509Cert
 * @brief Certificat X509 signé.
 *        peut-être créé depuis un certificat X509 au format DER
 *        où via une signature de X509Tbs.
 */
class X509Cert : public X509Tbs
{
public:
  /**
   * @function FromX509Tbs
   * @brief Transforme un X509Tbs signé en certificat X509.
   *        Le pointeur tbs est casté dynamiquement en X509Cert et est retourné.
   *        Celui-ci ne doit plus être utilisé par la suite.
   *
   * @param tbs Le certificat avant signature
   * @param signature La signature associée.
   */
  static X509Cert* FromX509Tbs(X509Tbs*           tbs,
                               const std::string& signature);

  /**
   * @function renew
   * @brief Fonction de renouvellement de certificat. Crée un X509Tbs
   *        prêt à être signé avec les nouvelles dates de validité.
   */
  X509Tbs* renew(const std::string& notBefore,
                 const std::string& notAfter);

  /**
   * @function fromDER
   * @brief Crée un X509Cert à partir d'un certificat sous sa forme DER.
   *
   * @param DER Chaîne de caractère contenant le certificat au format DER.
   */
  static X509Cert*  fromDER(const std::string& DER);

  /**
   * @function ~X509Cert
   * @brief Destructeur
   */
  virtual ~X509Cert();
private:
  /**
   * @function X509Cert
   * @brief Construit un object X509Cert vide.
   *     Important : Ce constructeur ne doit jamais être appelé explicitement.
   *    Il est appellé uniquement via newX509Request.
   */
  X509Cert();

public:
  /*
   * Retourne le certificat sous sa forme DER.
   */
  std::string      toDER() const;

protected:
  /* signature */
  std::string      signature;

  /* Representation du certificat issuer au format der */
  std::string      derX509;

  friend X509Req* newX509Request(const std::string &dn);
};
} // namespace LIBANSSIPKI

#endif /* X509CERT_H_ */
