#pragma once

#include <ostream>
#include <string>

#include "dns/detail/label_list.h"
#include "dns/detail/label_list/save_to.h"
#include "dns/detail/label_list/load_from.h"

namespace dns
{
   class rec_mx_t
   {
      public:
         void Exchange(const std::string& v)
         {
            m_exchange = v;
         }

         std::string Exchange() const
         {
            return m_exchange;
         }

         void Preference(const uint16_t v)
         {
            m_preference = v;
         }

         uint16_t Preference() const
         {
            return m_preference;
         }

         friend std::ostream& operator<<(std::ostream& os, const rec_mx_t& rhs)
         {
            return os << "[{pref = " << rhs.Preference() << ", " << rhs.Exchange() << "]";
         }

      private:
         uint16_t m_preference;
         std::string m_exchange;
   };

   inline void save_to(name_offset_tracker_t& tr, const rec_mx_t& r)
   {
      save_to(tr, r.Preference());
      save_to(tr, label_list_t{r.Exchange()});
   }

   template<>
   struct LoadImpl<rec_mx_t>
   {
      template<class InputIterator>
      static rec_mx_t impl(name_offset_tracker_t& tr, InputIterator& ii, InputIterator end)
      {
         rec_mx_t r{};

         r.Preference(load_from<uint16_t>(tr, ii, end));
         r.Exchange(load_from<label_list_t>(tr, ii, end).Name());

         return r;
      }
   };
}
