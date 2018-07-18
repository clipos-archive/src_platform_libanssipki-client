// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2013-2018 ANSSI. All Rights Reserved.
#ifndef UTILS_H_
# define UTILS_H_

# include "x509/x509req.h"

namespace LIBANSSIPKI
{

/** Union used to create a serial number using a counter*/
union serial_u {
  unsigned int count;
  char  str[20];
};

/**
 *  @function generateSerialNumber
 *  @brief    Génère un numéro de série de 20 octets en utilisant la
 *            ressource PKCS#11 comme générateur l'aléa
 */
std::string generateSerialNumber();

/**
 *  @function generateSerialNumber
 *  @brief    Génère un numéro de série de 20 octets en utilisant la
 *            ressource PKCS#11 comme générateur l'aléa pour les 16 derniers octets
 *            et utilise le compteur pour les 4 premiers.
 */
std::string generateSerialNumberWithCounter(unsigned long count);

/**
 *  @function DERtoX509
 *  @brief    Transforme un certificat DER en object OpenSSL X509
 *  @return   Retourne NULL si le parsing a échoué.
 */
X509* DERtoX509 (std::string der);

/**
 *  @function bio2string
 *  @brief    Récupère la chaine de charactères contenue dans un objet BIO (OpenSSL)
 */
std::string bio2string(BIO* b);

/**
 *  @function bio2string
 *  @brief    Crée un object BIO (OpenSSL) à partir d'une  chaine de charactères
 */
BIO* string2bio(const std::string& content);

/**
 *  @function keyUsageFromStr
 *  @brief  retourne le key usage à partir d'une chaine de charactère
 *  @throw  std::invalid_argument si la chaine n'est pas correcte
 */
KeyUsage_e keyUsageFromStr(const std::string& str);

/**
 *  @function extendedKeyUsageFromStr
 *  @brief  retourne le l'extended key usage à partir d'une chaine de charactère
 *  @throw  std::invalid_argument si la chaine n'est pas correcte
 */
ExtendedKeyUsage_e extendedKeyUsageFromStr(const std::string& str);

/**
 *  @function SANFromStr
 *  @brief  retourne le SubjectAltName à partir d'une chaine de charactère
 *  @throw  std::invalid_argument si la chaine n'est pas correcte
 */
SAN_e SANFromStr(const std::string& str);

}

#endif /* UTILS_H_ */
