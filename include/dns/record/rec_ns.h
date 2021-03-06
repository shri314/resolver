#pragma once

#include <ostream>
#include <string>

#include "dns/detail/label_list.h"
#include "dns/detail/label_list/save_to.h"
#include "dns/detail/label_list/load_from.h"

namespace dns
{
   class rec_ns_t
   {
      public:
         explicit rec_ns_t(std::string name)
            : m_name(std::move(name))
         {
         }

         explicit rec_ns_t()
            : rec_ns_t{{}}
         {
         }

         void Name(std::string v)
         {
            m_name = std::move(v);
         }

         const std::string& Name() const
         {
            return m_name;
         }

         friend std::ostream& operator<<(std::ostream& os, const rec_ns_t& rhs)
         {
            return os << "[" << rhs.Name() << "]";
         }

         friend bool operator==(const rec_ns_t& lhs, const rec_ns_t& rhs)
         {
            return lhs.Name() == rhs.Name();
         }

         static const rr_type_t m_type = dns::rr_type_t::rec_ns;

      private:
         std::string m_name;
   };

   inline void save_to(name_offset_tracker_t& tr, const rec_ns_t& r)
   {
      save_to(tr, label_list_t{r.Name()});
   }

   template<>
   struct LoadImpl<rec_ns_t>
   {
      template<class InputIterator>
      static rec_ns_t impl(name_offset_tracker_t& tr, InputIterator& ii, InputIterator end)
      {
         rec_ns_t r{};

         r.Name(load_from<label_list_t>(tr, ii, end).Name());

         return r;
      }
   };
}
