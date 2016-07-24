#pragma once

#include <ostream>
#include <string>

#include "dns/detail/label_list.h"
#include "dns/detail/label_list/save_to.h"
#include "dns/detail/label_list/load_from.h"

namespace dns
{
   class rec_cname_t
   {
      public:
         rec_cname_t(std::string name)
            : m_name(std::move(name))
         {
         }

         rec_cname_t()
            : rec_cname_t{{}}
         {
         }

         void Name(std::string name)
         {
            m_name = std::move(name);
         }

         const std::string& Name() const
         {
            return m_name;
         }

         friend std::ostream& operator<<(std::ostream& os, const rec_cname_t& rhs)
         {
            return os << "[name=" << rhs.Name() << "]";
         }

         friend bool operator==(const rec_cname_t& lhs, const rec_cname_t& rhs)
         {
            return lhs.Name() == rhs.Name();
         }

         static const rr_type_t m_type = dns::rr_type_t::rec_cname;

      private:
         std::string m_name;
   };

   inline void save_to(name_offset_tracker_t& tr, const rec_cname_t& r)
   {
      save_to(tr, label_list_t{r.Name()});
   }

   template<>
   struct LoadImpl<rec_cname_t>
   {
      template<class InputIterator>
      static rec_cname_t impl(name_offset_tracker_t& tr, InputIterator& ii, InputIterator end)
      {
         rec_cname_t r{};

         r.Name(load_from<label_list_t>(tr, ii, end).Name());

         return r;
      }
   };
}
