// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2013-2018 ANSSI. All Rights Reserved.
#ifndef P12_EXPORT_H_
# define P12_EXPORT_H_

# include <string>
# include <list>

namespace LIBANSSIPKI
{

  /**
   *  @function PKCS12_INIT
   *  @brief    Préparation d'une opération d'export P12 (NID_pbe_WithSHA1And3_Key_TripleDES_CBC)
   *            A partir du mot de passe, dérive la clé de wrapping, l'IV de wrapping et
   *            la clé pour le HMAC
   *            Le méchanisme de dérivation de mot de passe est spécifique à PKCS#12 et prend en paramètres
   *            le mot de passe, un nombre d'itération et un sel.
   *            Dans le cas de l'utilisation du proxy Caml-Crush, ce dernier est responsable de
   *            la généreration du mot de passe, du nombre d'iterations et du sel. Il s'occupe
   *            également des dérivations pour la génération des clés et de l'IV.
   *
   *  @param hKeyToWrap    (IN) handle vers la clé à exporter
   *  @param wrapKeyHandle (OUT) handle vers la clé de wrapping
   *  @param hmacKeyHandle (OUT) handle vers la clé de HMAC
   *  @param iter          (OUT) Nombre d'itérations utilisé pour la dérivation
   *  @param salt          (OUT) Sel utilisé pour la dérivation (Généré dans la ressource PKCS#11)
   *  @param password      Mot de passe, Avec Caml-Crush (OUT), Sans Calm-Crush (IN)
   *  @param withProxy     Utiliser le proxy PKCS#11 ou pas
   */
  void PKCS12_INIT(const CK_OBJECT_HANDLE      hKeyToWrap,
                   CK_OBJECT_HANDLE*           wrapKeyHandle,
                   CK_OBJECT_HANDLE*           hmacKeyHandle,
                   unsigned long*              iter,
                   std::string&                salt,
                   const std::string&          password,
                   const bool                  withProxy);

  /**
   *  @function extractToP12
   *  @brief    Exporte un certificat et sa cle privee proteges par un
   *            mot de passe au format PKCS#12
   *  @param    hPrivateKey   handle PKCS#11 vers la cle privee
   *  @param    certder       certificat a exporter au format DER
   *  @param    chain         liste de certificats parents ajoutes au fichier exporte
   *  @param    password      Mot de passe a utiliser pour la protection de la cle exportee.
   *            Lors de l'utilisation du proxy caml-crush, ce dernier est
   *            responsable pour la generation du mot de passe et des parametres
   *            de derivation du mot de passe.
   *  @param    withProxy     Utiliser le proxy PKCS#11 ou pas
   */
  std::string
  extractToP12(unsigned long            hPrivateKey,
               std::string              certder,
               std::list<std::string>   chain,
               std::string              password,
               const bool               withProxy);
}

#endif /* ! P12_EXPORT_H_ */
