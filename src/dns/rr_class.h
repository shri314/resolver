#pragma once

#include <ostream>

namespace dns
{
   enum class rr_class_t : uint16_t
   {
      reserved      = 0,        /* [RFC6895] */
      internet      = 1,        /* [RFC1035] */
      chaos         = 3,        /* [D. Moon, Chaosnet, A.I. Memo 628, Massachusetts Institute of Technology Artificial Intelligence Laboratory, June 1981.] */
      hesiod        = 4,        /* [Dyer, S., and F. Hsu, Hesiod, Project Athena Technical Plan - Name Service, April 1987.] */
      none          = 254,      /* [RFC2136] */
      any           = 255,      /* [RFC1035] */

      /* unassigned = 2, */
      /* unassigned = 5-253, */
      /* unassigned = 256-65279, */
      /* private    = 65280-65534, [RFC6895] */
      /* reserved   = 65535, [RFC6895] */

   };

   std::ostream& operator<<(std::ostream& os, rr_class_t rhs)
   {
      switch(rhs)
      {
         case rr_class_t::reserved:
            return os << "reserved";
         case rr_class_t::internet:
            return os << "internet";
         case rr_class_t::chaos:
            return os << "chaos";
         case rr_class_t::hesiod:
            return os << "hesiod";
         case rr_class_t::none:
            return os << "none";
         case rr_class_t::any:
            return os << "any";
      }

      return os << static_cast<unsigned>(rhs);
   }
}
