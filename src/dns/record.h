#pragma once

#include <ostream>
#include <string>

#include "dns/rr_type.h"
#include "dns/rr_class.h"

#include "dns/exception/bad_data_stream.h"

namespace dns
{
   class record_t
   {
      public:
         void RRName(const std::string& rrname)
         {
            m_rrname = rrname;
         }

         std::string RRName() const
         {
            return m_rrname;
         }

         void RRType(rr_type_t v)
         {
            m_rrtype = v;
         }

         rr_type_t RRType() const
         {
            return m_rrtype;
         }

         void RRClass(rr_class_t v)
         {
            m_rrclass = v;
         }

         rr_class_t RRClass() const
         {
            return m_rrclass;
         }

         void TTL(uint32_t v)
         {
            m_ttl = v;
         }

         uint32_t TTL() const
         {
            return m_ttl;
         }

         friend std::ostream& operator<<(std::ostream& os, const Question_t& rhs)
         {
            return os << "{ RRName=" << rhs.RRName() << ", RRType=" << rhs.RRType() << ", RRClass=" << rhs.RRClass() << ", TTL=" << rhs.TTL() << " }";
         }

         template<class OutputIterator>
         OutputIterator save_to(OutputIterator o)
         {
            return o;
         }

         template<class InputIterator>
         InputIterator load_from(InputIterator cur_pos, InputIterator end)
         {
            auto&& next = [&cur_pos, end]()
            {
               if(cur_pos != end)
                  return static_cast<uint8_t>(*cur_pos++);

               throw dns::exception::bad_data_stream("truncated", 1);
            };

            return cur_pos;
         }

      private:
         std::string m_rrname;
         rr_type_t m_rrtype = rr_type_t::rec_a;
         rr_class_t m_rrclass = rr_class_t::internet;
         int32_t m_ttl = 0;
   };
}
