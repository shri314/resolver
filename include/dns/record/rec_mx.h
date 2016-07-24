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
         explicit rec_mx_t(uint16_t preference, std::string exchange)
            : m_preference(preference)
            , m_exchange(std::move(exchange))
         {
         }

         explicit rec_mx_t()
            : rec_mx_t{0, {}}
         {
         }

         void Preference(const uint16_t v)
         {
            m_preference = v;
         }

         uint16_t Preference() const
         {
            return m_preference;
         }

         void Exchange(std::string v)
         {
            m_exchange = std::move(v);
         }

         const std::string& Exchange() const
         {
            return m_exchange;
         }

         friend std::ostream& operator<<(std::ostream& os, const rec_mx_t& rhs)
         {
            return os << "[preference=" << rhs.Preference() << ", exchange=" << rhs.Exchange() << "]";
         }

         friend bool operator==(const rec_mx_t& lhs, const rec_mx_t& rhs)
         {
            return lhs.Preference() == rhs.Preference() &&
                   lhs.Exchange() == rhs.Exchange();
         }

         static const rr_type_t m_type = dns::rr_type_t::rec_mx;

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
