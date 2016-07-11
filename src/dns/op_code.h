#pragma once

#include <ostream>

namespace dns
{
   enum class op_code_t : uint8_t
   {
      query  = 0,
      iquery = 1,
      status = 2,

      notify = 4,
      update = 5,
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
         default:
            return os << static_cast<unsigned>(rhs);
      }
   }
}
