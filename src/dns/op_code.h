#pragma once

#include <ostream>

namespace dns
{
   enum class op_code_t : uint8_t
   {
      query  = 0,    /* [RFC1035] */
      iquery = 1,    /* (Inverse Query, OBSOLETE) [RFC3425] */
      status = 2,    /* [RFC1035] */
      notify = 4,    /* [RFC1996] */
      update = 5,    /* [RFC2136] */

      /* unassigned = 3, */
      /* unassigned = 6-15, */
   };

   std::ostream& operator<<(std::ostream& os, op_code_t rhs)
   {
      switch(rhs)
      {
         case op_code_t::query:
            return os << "query";
         case op_code_t::iquery:
            return os << "iquery";
         case op_code_t::status:
            return os << "status";
         case op_code_t::notify:
            return os << "notify";
         case op_code_t::update:
            return os << "update";
      }

      return os << static_cast<unsigned>(rhs);
   }
}
