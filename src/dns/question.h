#pragma once

#include <ostream>
#include <string>

#include "dns/rr_type.h"
#include "dns/rr_class.h"

#include "dns/exception/bad_data_stream.h"

namespace dns
{
   class question_t
   {
      public:
         void QName(const std::string& qname)
         {
            m_qname = qname;
         }

         std::string QName() const
         {
            return m_qname;
         }

         void QType(rr_type_t v)
         {
            m_qtype = v;
         }

         rr_type_t QType() const
         {
            return m_qtype;
         }

         void QClass(rr_class_t v)
         {
            m_qclass = v;
         }

         rr_class_t QClass() const
         {
            return m_qclass;
         }

         friend std::ostream& operator<<(std::ostream& os, const question_t& rhs)
         {
            return os << "{ QName=" << rhs.QName() << ", QType=" << rhs.QType() << ", QClass=" << rhs.QClass() << " }";
         }

         template<class OutputIterator>
         OutputIterator save_to(OutputIterator o)
         {
            // split the qname into domains.
            // emit { number, label } ... null - lookup m_labels to emit offsets, also store offsets just emitted.
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
         std::string m_qname;
         rr_type_t m_qtype = rr_type_t::rec_a;
         rr_class_t m_qclass = rr_class_t::internet;
   };
}
