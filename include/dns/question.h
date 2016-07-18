#pragma once

#include <ostream>
#include <string>

#include "dns/rr_type.h"
#include "dns/rr_class.h"
#include "dns/detail/label_list.h"
#include "dns/detail/label_list/save_to.h"
#include "dns/detail/label_list/load_from.h"

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

   template<>
   struct LoadImpl<question_t>
   {
      template<class InputIterator>
      static question_t impl(name_offset_tracker_t& tr, InputIterator& ii, InputIterator end)
      {
         question_t q{};

         q.Name(load_from<label_list_t>(tr, ii, end).Name());
         q.Type(static_cast<rr_type_t>(load_from<uint16_t>(tr, ii, end)));
         q.Class(static_cast<rr_class_t>(load_from<uint16_t>(tr, ii, end)));

         return q;
      }
   };
}
