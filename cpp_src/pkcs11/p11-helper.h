// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2013-2018 ANSSI. All Rights Reserved.
#ifndef P11_HELPER_H_
# define P11_HELPER_H_

# include "pkcs11/pkcs11.h"
# include "x509/public-key.h"
# include "x509/private-key.h"
# include "x509/x509req.h"
# include "x509/x509cert.h"
# include "pkcs11/p11-exception.h"

namespace LIBANSSIPKI
{
enum keyUsage {
  USAGE_SIGNATURE = 1,
  USAGE_ENCRYPTION = 2,
};

class P11Helper {
private:
  /**
   *  @function P11Helper
   *  @brief    Création d'un object P11Helper vide
   */
  P11Helper();
public:
  /**
   *  @function P11Helper
   *  @brief    Destruction d'un object P11Helper.
   *            Si l'object est connecté à une session, la session est coupée
   *            et le module est déchargé.
   */
  ~P11Helper();
public:
  /**
   *  @function initInstance
   *  @brief    Initialisation du singleton vers la ressource PKCS#11 principale
   */
  static void      initInstance(P11Helper*  instance);
  /**
   *  @function getInstance
   *  @brief    retourne le singleton vers la ressource PKCS#11 principale
   */
  static P11Helper*  getInstance();

  /**
   *  @function initInstance
   *  @brief    ferme et détruit le singleton vers la ressource PKCS#11 principale
   */
  static void      closeInstance();

  /**
   *  @function connect
   *  @brief    Connection à une ressource PKCS#11
   *
   *  @param    module_path   chemin vers le middleware PKCS#11 (fichier .so)
   *  @param    pin           code pin utilisateur
   *  @param    label         label du token à rechercher parmis les slots disponibles.
   *  @param    force_slot_id Force l'utilisation d'un slot particulier (pas de recherche de label)
   *  @param    slot_id       slot à utiliser si force_slot_id est vrai.
   */
  static P11Helper*  connect(const std::string&  module_path,
                             const char*         pin,
                             const std::string&  label,
                             bool                force_slot_id,
                             unsigned long       slot_id);

  /**
   *  @function getObjectHandleByLabel
   *  @brief    Recherche un object par son label et son type.
   */
  int getObjectHandleByLabel(const CK_OBJECT_CLASS  type,
                             const std::string      label,
                             CK_OBJECT_HANDLE*      ret);

  /**
   *  @function getObjectHandleByID
   *  @brief    Recherche un object par son ID et son type.
   */
  int getObjectHandleByID(const CK_OBJECT_CLASS cls,
                          const unsigned int    id,
                          CK_OBJECT_HANDLE*     ret);

  /**
   *  @function findCertificateBySubject
   *  @brief    Recherche un certificat par sujet (DER subject)
   */
  int findCertificateBySubject(const std::string& subject,
                               CK_OBJECT_HANDLE*  ret);

  /**
   *  @function listAvailableSignAlgorithms
   *  @brief    Retourne la liste des algorithms de signature disponible sur la ressource
   */
  std::list<std::string> listAvailableSignAlgorithms() const;

  /**
   *  @function generateRSAKeyPair
   *  @brief    Génère une bi-clé RSA
   *
   *  @param    key_length taille de la clé à générer
   *  @param    id ID de la clé à générer
   *  @param    sensitive Si vrai, la clé sera marquée comme sensitive et non extractable
   *  @param	label Label de la clé
   *  @param	usage Futur usage de la clé
   *  @param    hPublicKey  handle vers la clé publique générée
   *  @param    hPrivateKey  handle vers la clé privée générée
   */
  void generateRSAKeyPair(const CK_ULONG       key_length,
                          const unsigned long  id,
                          const bool           sensitive,
			  const std::string&   label,
			  const keyUsage       usage,
                          CK_OBJECT_HANDLE*    hPublicKey,
                          CK_OBJECT_HANDLE*    hPrivateKey);

  /**
   *  @function generateECKeyPair
   *  @brief    Génère une bi-clé EC
   *
   *  @param    key_length  taille de la clé à générer
   *  @param    id          ID de la clé à générer
   *  @param    sensitive   Si vrai, la clé sera marquée comme sensitive et non extractable
   *  @param    hPublicKey  handle vers la clé publique générée
   *  @param    hPrivateKey handle vers la clé privée générée
   */
  void generateECKeyPair(const std::string&     ecparams,
                         const unsigned int    id,
                         const bool        sensitive,
                         CK_OBJECT_HANDLE*    hPublicKey,
                         CK_OBJECT_HANDLE*    hPrivateKey);

  /**
   *  @function sign
   *  @brief    Signe un bloc de données dans la ressource PKCS#11
   *  @param    data      données à signer
   *  @param    mechanism méchanisme de signature PKCS#11 à utiliser.
   *  @param    hKey      handle vers la clé privée à utiliser
   */
  std::string sign(const std::string&     data,
                   CK_MECHANISM_TYPE      mechanism,
                   const CK_OBJECT_HANDLE hKey);

  /**
   *  @function wrap
   *  @brief    Wrap une clé privée avec une autre clé.
   *
   *  @param    hKeyToWrap    Handle vers la clé à wrapper
   *  @param    hwrappingKey  Handle vers la clé de wrapping
   *  @param    mechanism     Méchanisme de wrapping à utiliser
   *  @param    iv            Valeur d'initialisation pour le wrapping
   */
  std::string wrap(CK_OBJECT_HANDLE        hKeyToWrap,
                   CK_OBJECT_HANDLE        hwrappingKey,
                   CK_MECHANISM_TYPE       mechanism,
                   const std::string&      iv);

  /**
   *  @function extractPublicKey
   *  @brief    Récupère une clé publique depuis son handle
   */
  PublicKey* extractPublicKey(CK_OBJECT_HANDLE  obj);

  /**
   *  @function extractPublicKey
   *  @brief    Récupère une clé privée RSA depuis son handle
   *  @param    obj   Handle de la clé privée à extraire
   */
  RSAPrivateKey* extractRSAPrivateKey(CK_OBJECT_HANDLE  obj);

  /**
   *  @function injectRSAPrivateKey
   *  @brief    Écrit une clé privée RSA dans la ressource
   *  @param    key         Clé privée à injecter
   *  @param    id          ID de lé clé à injecter
   *  @param    sensitive   Si vrai, la clé sera marquée comme sensitive et non extractable
   *  @param    label       Label de lé clé à injecter
   *  @param    usage       Usage de lé clé à injecter
   */
  void writeRSAPrivateKey(const RSAPrivateKey& key,
			  const unsigned long  id,
			  const bool           sensitive,
			  const std::string&   label,
			  const keyUsage       usage);

  /**
   *  @function writeCertificate
   *  @brief    Ecrit un certificat dans la ressource
   *
   *  @param cert     Certificat
   *  @param cryptoID ID de l'object à créer
   *  @param label    Label de l'object à créer
   */
  void  writeCertificate(const X509Cert&  cert,
                         unsigned int     cryptoID,
			 const std::string& label);

  /**
   *  @function extractCertificate
   *  @brief    Récupère un certificat depuis son handle
   */
  std::string extractCertificate(CK_OBJECT_HANDLE obj);

  /**
   *  @function generateRandom
   *  @brief    Génère un aléa de taille 'size' dans le buffer
   */
  void generateRandom(unsigned char* buffer, size_t size);

  /**
   *  @function generateRandom
   *  @brief    Génère un aléa de taille 'size' et le retourne dans une string
   */
  std::string generateRandom(size_t size);

  /**
   *  @function createObject
   *  @brief    Crée un objet dans la ressource
   *
   *  @param    objectTemplate Template de l'objet à injecter.
   *  @param    objectTemplateLength Nombre d'entrées dans le template
   *  @param    hObject         hObject Handle vers l'objet créé.
   */
  void  createObject(CK_ATTRIBUTE*      objectTemplate,
                     unsigned long      objectTemplateLength,
                     CK_OBJECT_HANDLE*  hObject);

private:
  bool loadModule(const std::string& module_path);
  void login(int login_type, const char *pin);
  /* Find a token from the slot availables */
  bool openTokenWithLabel(const std::string& label);
  bool openTokenWithSlotId(unsigned long id);
  void fillMechanismList();
  void fetchSlots();
  template <typename TYPE> TYPE getAttr(CK_ULONG attr, CK_OBJECT_HANDLE obj);
  template <typename TYPE> void getAttr(CK_ULONG cka_value, CK_OBJECT_HANDLE obj, TYPE*& data, CK_ULONG& size);

private:

  void *module;
  CK_FUNCTION_LIST_PTR p11;
  CK_SLOT_ID_PTR p11_slots;

  CK_ULONG p11_num_slots;
  CK_SESSION_HANDLE hSession;

  CK_SLOT_ID current_slot;

  std::list<CK_MECHANISM_TYPE> signMechanisms;

  static P11Helper* instance;

  // Dans le cas d'utilisation du proxy Caml-Crush, la fonction PKCS12_INIT
  // doit effectuer un appel détourné à la fonction C_WrapKey (dans l'attribut p11 de l'object).
  friend void PKCS12_INIT_WITH_PROXY(const CK_OBJECT_HANDLE  hKeyToWrap,
                    CK_OBJECT_HANDLE*       wrapKeyHandle,
                    CK_OBJECT_HANDLE*       hmacKeyHandle,
                    unsigned long*          iter,
                    std::string&            salt,
                    const std::string&      password);
};
} // namespace LIBANSSIPKI

#endif /* P11_HELPER_H_ */
