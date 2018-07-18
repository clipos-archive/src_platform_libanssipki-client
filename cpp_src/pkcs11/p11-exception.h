// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2013-2018 ANSSI. All Rights Reserved.
#ifndef P11_EXCEPTION_H_
# define P11_EXCEPTION_H_

# include <exception>
# include <string>

/// Class describing the exceptions thrown by the P11 calls
/**
 * This class allows for a unified way of signaling errors inside P11Helper code.
 */

namespace LIBANSSIPKI
{
class P11Exception : public std::exception {
 public:

  /**
   * Exception constructor allowing for a detailled message.
   *
   * @param rv Returv value according to P11 standard.
   * @param details String containing details about the error encountered.
   */
  P11Exception (const unsigned int rv, const std::string& details);

  /**
   * Create a P11Exception with a message containing the function name and the
   *
   *
   * @param rv error code according to P11 standard.
   * @param details String containing details about the error encountered.
   * @param ckaParam CKA attribute value.
   */
  P11Exception (const unsigned int rv, const std::string& functionName, unsigned int ckaParam);

  /**
   * Constructor by copy.
   *
   * @param e an existing P11Exception.
   */
  P11Exception (const P11Exception& e) : _rv (e._rv), _details (e._details) {};


  /**
   * Standard function to produce a printable message when the
   * exception is caught.
   *
   * @return the message to be printed.
   */
  virtual const char* what () const throw () {return _details.c_str(); };

  /**
   * Simple accessor for the error type.
   */
  unsigned int rv () const { return _rv; }

  /**
   * Simple accessor for the detailed message if available.
   */
  const std::string& details () const { return _details; }

  /**
   * Simple destructor
   */
  virtual ~P11Exception() throw () {};

 private:
  unsigned int _rv;  /**< Error type */
  std::string _details;     /**< Detailed message. If empty, a default message corresponding to the error type is returned. */

  P11Exception () {}
  const P11Exception& operator= (const P11Exception& e);
};
} // namespace LIBANSSIPKI

#endif /* !P11_EXCEPTION_H_ */
