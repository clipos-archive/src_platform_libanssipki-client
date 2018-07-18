%module anssipki


%exception {
  try {
    $action
  } catch (LIBANSSIPKI::P11Exception& e) {
    PyErr_SetString(PyExc_StandardError, const_cast<char*>(e.what()));
    return NULL;
  } catch (std::logic_error& e) {
    PyErr_SetString(PyExc_StandardError, const_cast<char*>(e.what()));
    return NULL;
  }
}

%{
# include "x509/public-key.h"
# include "pkcs11/p11-helper.h"
# include "x509/x509req.h"
# include "x509/x509tbs.h"
# include "x509/x509cert.h"
# include "x509/x509crl.h"
# include "utils.h"
# include "algos.h"
# include "p12_export.h"
# include "csr_export.h"

using namespace LIBANSSIPKI;
%}

%apply CK_OBJECT_HANDLE* OUTPUT{CK_OBJECT_HANDLE*		hPublicKey,
							 	CK_OBJECT_HANDLE*		hPrivateKey}
%apply CK_OBJECT_HANDLE* OUTPUT{CK_OBJECT_HANDLE*		ret}

%include stl.i
%include <std_list.i>
%include <std_string.i>
%include typemaps.i


%template(StringList) std::list<std::string>;


%include "x509/public-key.h"
%include "x509/x509req.h"
%include "x509/x509tbs.h"
%include "x509/x509cert.h"
%include "x509/x509crl.h"
%include "pkcs11/p11-helper.h"
%include "utils.h"
%include "algos.h"
%include "p12_export.h"
%include "csr_export.h"

typedef unsigned long int CK_ULONG;
typedef unsigned long CK_MECHANISM_TYPE;
#define ck_object_handle_t CK_OBJECT_HANDLE
#define ck_object_class_t CK_OBJECT_CLASS
typedef unsigned long ck_object_handle_t;
typedef unsigned long ck_object_class_t;

#define CK_INVALID_HANDLE	(0UL)
#define CKO_DATA		(0UL)
#define CKO_CERTIFICATE		(1UL)
#define CKO_PUBLIC_KEY		(2UL)
#define CKO_PRIVATE_KEY		(3UL)
#define CKO_SECRET_KEY		(4UL)
#define CKO_HW_FEATURE		(5UL)
#define CKO_DOMAIN_PARAMETERS	(6UL)
#define CKO_MECHANISM		(7UL)
#define CKO_VENDOR_DEFINED	(1UL << 31)

