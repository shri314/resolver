#pragma once

#include <ostream>

namespace dns
{
   enum class r_code_t : uint8_t
   {
      no_error   = 0,
      form_err   = 1,
      serv_fail  = 2,
      nx_domain  = 3,
      not_imp    = 4,
      refused    = 5,
      yx_domain  = 6,
      yx_rrset   = 7,
      nx_rrset   = 8,
      not_auth   = 9,

      bad_vers   = 16,
      bad_sig    = 17,
      bad_key    = 18,
      bad_time   = 19,
      bad_mode   = 20,
      bad_name   = 21,
      bad_alg    = 22,
      bad_trunc  = 23,
      bad_cookie = 24,
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
            return os << "bad_vers";
         case r_code_t::bad_sig:
            return os << "bad_sig";
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

         default:
            return os << static_cast<unsigned>(rhs);
      }
   }
}
