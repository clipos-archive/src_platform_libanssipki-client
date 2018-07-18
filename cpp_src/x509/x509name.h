// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2013-2018 ANSSI. All Rights Reserved.
#ifndef X509NAME_H_
# define X509NAME_H_

# include <list>
# include <openssl/x509.h>

namespace LIBANSSIPKI
{
enum DN_e {
  DN_CommonName,
  DN_SurName,
  DN_Organization,
  DN_OrganizationalUnit,
  DN_Country,
  DN_State,
  DN_Locality
};

class X509Name {
public:
  /**
   * @function X509Name
   * @brief Crée un X509Name vide
   */
  X509Name() {};
  /**
   * @function X509Name
   * @brief Copie un X509Name
   */
  X509Name(const X509Name& name) : entries(name.entries) {};

  /**
   * @function X509Name
   * @brief Crée un X509Name à partir d'une chaine de charactère
   *        au format clé=valeur séparés par des ','
   * @throw std::invalid_argument Une exception est levé si la chaine n'a
   *        pas été correctement parsée (format invalide ou champs inconnus)
   */
  X509Name(const std::string& dn);

  /**
   * @function toString
   * @brief retourne la reprentation textuelle
   */
  std::string toString() const;

  /**
   * @function setDN
   * @brief Crée un X509Name à partir d'une chaine de charactère
   *        au format clé=valeur séparés par des ','
   * @throw std::invalid_argument Une exception est levé si la chaine n'a
   *        pas été correctement parsée (format invalide ou champs inconnus)
   */
  void     setDN(const std::string& dn);


  /**
   * @function addEntry
   * @brief Ajoute une nouvelle entrée depuis une chaine de charactère au format
   *        clé=valeur
   */
  void    addEntry(DN_e type, const std::string& value);

  /**
   * @function toOSSLX509_NAME
   * @brief Retourne la representation OpenSSL de l'objet.
   */
  X509_NAME*  toOSSLX509_NAME() const;

  /**
   * @function fromOSSLX509_NAME
   * @brief Crée un X509Name à partir de la representation OpenSSL
   */
  void    fromOSSLX509_NAME(X509_NAME*  name);

  /**
   * @function toDER
   * @brief Retourne la representation au format DER
   */
  std::string   toDER() const;

private:
  // Liste des couples clé,valeur.
  std::list<std::pair<DN_e, std::string> > entries;
};
} // namespace LIBANSSIPKI

#endif /* !X509NAME_H_ */
