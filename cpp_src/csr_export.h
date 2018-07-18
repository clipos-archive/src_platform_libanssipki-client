// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2013-2018 ANSSI. All Rights Reserved.
#ifndef CSR_EXPORT_H_
# define CSR_EXPORT_H_

namespace LIBANSSIPKI
{

/**
 *  @function exportToCSR
 *  @brief    Creation d'une requete de signature a partir d'un certificat deja existant.
 *            Cette fonction est utilisee lors d'un rattachement d'une AC racine a une autre AC.
 *  @param    hPrivateKey   handle PKCS#11 vers la cle privee
 *  @param    certder       certificat a exporter au format DER
 */
std::string
exportToCSR(unsigned long     hPrivateKey,
            const std::string&    certder);
}

#endif /* ! CSR_EXPORT_H_ */
