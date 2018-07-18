// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2013-2018 ANSSI. All Rights Reserved.
#include <stdexcept>

#include "pkcs11/p11-helper.h"
#include "utils.h"
#include "algos.h"

namespace LIBANSSIPKI {

std::string
exportToCSR(unsigned long     hPrivateKey,
             const std::string&    certder)
{
   BIO*      bi = NULL;
   X509*       x = NULL;
   X509_REQ*   csr = NULL;
   std::string   signature;
   unsigned char*  der = NULL;
   size_t      derLength;
   CK_MECHANISM_TYPE p11SigAlgo = 0;
   std::string   csrDer;

   // DER -> X509*
   bi = BIO_new(BIO_s_mem());
   BIO_write(bi, certder.c_str(), certder.size());
   x = d2i_X509_bio(bi, NULL);
   BIO_free(bi);

   // On s'assure que le parsing c'est bien passé.
   if (!x)
     throw std::logic_error("Error when parsing certificate.");

   p11SigAlgo = SignAlgoNIDToP11Mech(OBJ_obj2nid(x->cert_info->signature->algorithm));
   if (p11SigAlgo == 0)
   {
     X509_free(x);
     throw std::logic_error("Sign algorithm not supported.");
   }


   // X509* -> X509_REQ*
   csr = X509_to_X509_REQ(x, NULL, NULL /* Private Key, digest NULL = No signature*/);
   csr->req_info->attributes = NULL;


   // Signature de la CSR = algo de signature du certificat.
   X509_ALGOR_set0(csr->sig_alg, x->cert_info->signature->algorithm, V_ASN1_NULL, NULL);

   // Création du bloc CSR à signer.
   derLength = ASN1_item_i2d((ASN1_VALUE*)(csr->req_info),
                 &der, ASN1_ITEM_rptr(X509_REQ_INFO));
   csrDer = std::string((char*)der, derLength);
   OPENSSL_free(der);

   // Opération de signature dans la ressource P11
   signature = P11Helper::getInstance()->sign(csrDer, p11SigAlgo, hPrivateKey);

   // Ajout de la signature dans la CSR.
   ASN1_BIT_STRING_set(csr->signature,
       (unsigned char*)(signature.c_str()), signature.size());
   csr->signature->flags &= ~(ASN1_STRING_FLAG_BITS_LEFT|0x07);
   csr->signature->flags |= ASN1_STRING_FLAG_BITS_LEFT;

   // X509_REQ* -> DER
   bi = BIO_new(BIO_s_mem());
   i2d_X509_REQ_bio(bi, csr);
   csrDer = bio2string(bi);
   BIO_free(bi);

   X509_free(x);

   return csrDer;
}

}
