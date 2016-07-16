#pragma once

#include <ostream>

namespace dns
{
   enum class r_code_t : uint8_t
   {
      no_error   = 0,   /* No Error, [RFC1035] */
      form_err   = 1,   /* Format Error, [RFC1035] */
      serv_fail  = 2,   /* Server Failure, [RFC1035] */
      nx_domain  = 3,   /* Non-Existent Domain, [RFC1035] */
      not_imp    = 4,   /* Not Implemented, [RFC1035] */
      refused    = 5,   /* Query Refused, [RFC1035] */
      yx_domain  = 6,   /* Name Exists when it should not, [RFC2136][RFC6672] */
      yx_rrset   = 7,   /* RR Set Exists when it should not, [RFC2136] */
      nx_rrset   = 8,   /* RR Set that should exist does not, [RFC2136] */
      not_auth   = 9,   /* Server Not Authoritative for zone, [RFC2136], Not Authorized, [RFC2845] */
      not_zone   = 10,  /* Name not contained in zone, [RFC2136] */
      bad_vers   = 16,  /* Bad OPT Version, [RFC6891] */
      bad_sig    = 16,  /* TSIG Signature Failure, [RFC2845] */
      bad_key    = 17,  /* Key not recognized, [RFC2845] */
      bad_time   = 18,  /* Signature out of time window, [RFC2845] */
      bad_mode   = 19,  /* Bad TKEY Mode, [RFC2930] */
      bad_name   = 20,  /* Duplicate key name, [RFC2930] */
      bad_alg    = 21,  /* Algorithm not supported, [RFC2930] */
      bad_trunc  = 22,  /* Bad Truncation, [RFC4635] */
      bad_cookie = 23,  /* Bad/missing Server Cookie, [RFC7873] */

      /* unassigned = 11-15, */
      /* unassigned = 24-3840, */
      /* reserved = 3841-4095, private use, [RFC6895] */
      /* unassigned = 4096-65534, */
      /* reserved = 65535, can be allocated by Standards Action, [RFC6895] */
   };

   std::ostream& operator<<(std::ostream& os, r_code_t rhs)
   {
      switch(rhs)
      {
         case r_code_t::no_error:
            return os << "no_error";
         case r_code_t::form_err:
            return os << "form_err";
         case r_code_t::serv_fail:
            return os << "serv_fail";
         case r_code_t::nx_domain:
            return os << "nx_domain";
         case r_code_t::not_imp:
            return os << "not_imp";
         case r_code_t::refused:
            return os << "refused";
         case r_code_t::yx_domain:
            return os << "yx_domain";
         case r_code_t::yx_rrset:
            return os << "yx_rrset";
         case r_code_t::nx_rrset:
            return os << "nx_rrset";
         case r_code_t::not_auth:
            return os << "not_auth";
         case r_code_t::bad_vers:
            return os << "bad_vers|bad_sig";
         case r_code_t::bad_key:
            return os << "bad_key";
         case r_code_t::bad_time:
            return os << "bad_time";
         case r_code_t::bad_mode:
            return os << "bad_mode";
         case r_code_t::bad_name:
            return os << "bad_name";
         case r_code_t::bad_alg:
            return os << "bad_alg";
         case r_code_t::bad_trunc:
            return os << "bad_trunc";
         case r_code_t::bad_cookie:
            return os << "bad_cookie";
      }

      return os << static_cast<unsigned>(rhs);
   }
}
