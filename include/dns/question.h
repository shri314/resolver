#pragma once

#include <ostream>
#include <string>

#include "dns/rr_type.h"
#include "dns/rr_class.h"
#include "dns/label_list.h"

#include "dns/exception/bad_data_stream.h"

namespace dns
{
   class question_t
   {
      public:
         void Name(const std::string& qname)
         {
            m_qname = qname;
         }

         std::string Name() const
         {
            return m_qname;
         }

         void Type(rr_type_t v)
         {
            m_type = v;
         }

         rr_type_t Type() const
         {
            return m_type;
         }

         void Class(rr_class_t v)
         {
            m_class = v;
         }

         rr_class_t Class() const
         {
            return m_class;
         }

         friend std::ostream& operator<<(std::ostream& os, const question_t& rhs)
         {
            return os << "{ Name=" << rhs.Name() << ", Type=" << rhs.Type() << ", Class=" << rhs.Class() << " }";
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
         rr_type_t m_type = rr_type_t::rec_a;
         rr_class_t m_class = rr_class_t::internet;
   };

   inline void save_to(name_offset_tracker_t& tr, const question_t& q)
   {
      save_to(tr, label_list_t{q.Name()});
      save_to(tr, static_cast<uint16_t>(q.Type()));
      save_to(tr, static_cast<uint16_t>(q.Class()));
   }

   template<class InputIterator>
   void load_from(name_offset_tracker_t& tr, InputIterator& i, InputIterator end, question_t& q)
   {
      {
         label_list_t ll;
         load_from(tr, i, end, ll);
         q.Name(ll.Name());
      }

      {
         uint16_t v;
         load_from(tr, i, end, v);
         q.Type(static_cast<rr_type_t>(v));
      }

      {
         uint16_t v;
         load_from(tr, i, end, v);
         q.Class(static_cast<rr_class_t>(v));
      }
   }
}
