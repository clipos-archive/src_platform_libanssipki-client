// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2013-2018 ANSSI. All Rights Reserved.
#ifndef ALGOS_H_
# define ALGOS_H_

# include <openssl/x509.h>
# include "pkcs11/pkcs11.h"
# include "x509/public-key.h"

namespace LIBANSSIPKI
{

/**
 *  @struct s_sign_algo_table
 *  @brief  triplet (algo sous forme textuelle, NID de l'algo,
                      mechism p11 de l'algo)
 */
typedef struct
{
  const char*      str;
  unsigned long    NID;
  CK_MECHANISM_TYPE  p11_mechanism;
}    s_sign_algo_table;

/**
 *  @function SignAlgoP11MechToString
 *  @brief    retourne la forme textuelle d'un algo a partir du mechanisme p11
 *  @return   retourne NULL si inconnu.
 */
const char* SignAlgoP11MechToString(CK_MECHANISM_TYPE p11_mechanism);

/**
 *  @function SignAlgoP11MechToNID
 *  @brief    retourne le NID d'un algo a partir du mechanisme p11
 *  @return   retourne 0 si inconnu.
 */
unsigned long SignAlgoP11MechToNID(CK_MECHANISM_TYPE p11_mechanism);

/**
 *  @function SignAlgoP11MechToString
 *  @brief    retourne le mechanisme p11 a partir de la forme textuelle d'un algo
 *  @return   retourne 0 si inconnu.
 */
CK_MECHANISM_TYPE SignAlgoStrToP11Mech(const char *str);

/**
 *  @function SignAlgoP11MechToString
 *  @brief    retourne le NID d'un algo a partir de la forme textuelle d'un algo
 *  @return   retourne 0 si inconnu.
 */
unsigned long SignAlgoStrToNID(const char *str);

/**
 *  @function SignAlgoP11MechToString
 *  @brief    retourne la forme textuelle d'un algo a partir du NID
 *  @return   retourne NULL si inconnu.
 */
const char* SignAlgoNIDToStr(unsigned long NID);

/**
 *  @function SignAlgoP11MechToString
 *  @brief    retourne le mechanisme p11 d'un algo a partir du NID
 *  @return   retourne 0 si inconnu.
 */
CK_MECHANISM_TYPE SignAlgoNIDToP11Mech(unsigned long NID);

/**
 *  @function keyPairAlgoFromStr
 *  @brief  retourne le key_pair_algo_e à partir d'une chaine de charactère
 *  @throw  std::invalid_argument si la chaine n'est pas correcte
 */
key_pair_algo_e keyPairAlgoFromStr(const std::string& str);


}

#endif /* ! ALGOS_H_ */
