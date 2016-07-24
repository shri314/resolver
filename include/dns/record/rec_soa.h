#pragma once

#include <ostream>
#include <string>

#include "dns/detail/label_list.h"
#include "dns/detail/label_list/save_to.h"
#include "dns/detail/label_list/load_from.h"

namespace dns
{
   class rec_soa_t
   {
      public:
         rec_soa_t(std::string mname,
                   std::string rname,
                   uint32_t serial,
                   uint32_t refresh_interval,
                   uint32_t retry_interval,
                   uint32_t expire_interval,
                   uint32_t minimum_ttl
                  )
            : m_mname(std::move(mname))
            , m_rname(std::move(rname))
            , m_serial(serial)
            , m_refresh_interval(refresh_interval)
            , m_retry_interval(retry_interval)
            , m_expire_interval(expire_interval)
            , m_minimum_ttl(minimum_ttl)
         {
         }

         rec_soa_t()
            : rec_soa_t{"", "", 0, 0, 0, 0, 0}
         {
         }

         void MName(std::string v)
         {
            m_mname = std::move(v);
         }

         const std::string& MName() const
         {
            return m_mname;
         }

         void RName(std::string v)
         {
            m_rname = std::move(v);
         }

         const std::string& RName() const
         {
            return m_rname;
         }

         void Serial(uint32_t v)
         {
            m_serial = std::move(v);
         }

         uint32_t Serial() const
         {
            return m_serial;
         }

         void RefreshInterval(uint32_t v)
         {
            m_refresh_interval = std::move(v);
         }

         uint32_t RefreshInterval() const
         {
            return m_refresh_interval;
         }

         void RetryInterval(uint32_t v)
         {
            m_retry_interval = std::move(v);
         }

         uint32_t RetryInterval() const
         {
            return m_retry_interval;
         }

         void ExpireInterval(uint32_t v)
         {
            m_expire_interval = std::move(v);
         }

         uint32_t ExpireInterval() const
         {
            return m_expire_interval;
         }

         void MinimumTTL(uint32_t v)
         {
            m_minimum_ttl = std::move(v);
         }

         uint32_t MinimumTTL() const
         {
            return m_minimum_ttl;
         }

         friend std::ostream& operator<<(std::ostream& os, const rec_soa_t& rhs)
         {
            return os << "[mname=" << rhs.MName()
                   << ", rname="   << rhs.RName()
                   << ", serial="  << rhs.Serial()
                   << ", refresh=" << rhs.RefreshInterval()
                   << ", retry="   << rhs.RetryInterval()
                   << ", expire="  << rhs.ExpireInterval()
                   << ", minimum=" << rhs.MinimumTTL()
                   << "]";
         }

         friend bool operator==(const rec_soa_t& lhs, const rec_soa_t& rhs)
         {
            return lhs.MName()           == rhs.MName() &&
                   lhs.RName()           == rhs.RName() &&
                   lhs.Serial()          == rhs.Serial() &&
                   lhs.RefreshInterval() == rhs.RefreshInterval() &&
                   lhs.RetryInterval()   == rhs.RetryInterval() &&
                   lhs.ExpireInterval()  == rhs.ExpireInterval() &&
                   lhs.MinimumTTL()      == rhs.MinimumTTL();
         }

         static const rr_type_t m_type = dns::rr_type_t::rec_soa;

      private:
         std::string m_mname;
         std::string m_rname;
         uint32_t m_serial = 0;
         uint32_t m_refresh_interval = 0;
         uint32_t m_retry_interval = 0;
         uint32_t m_expire_interval = 0;
         uint32_t m_minimum_ttl = 0;
   };

   inline void save_to(name_offset_tracker_t& tr, const rec_soa_t& r)
   {
      save_to(tr, label_list_t{r.MName()});
      save_to(tr, label_list_t{r.RName()});
      save_to(tr, static_cast<uint32_t>(r.Serial()));
      save_to(tr, static_cast<uint32_t>(r.RefreshInterval()));
      save_to(tr, static_cast<uint32_t>(r.RetryInterval()));
      save_to(tr, static_cast<uint32_t>(r.ExpireInterval()));
      save_to(tr, static_cast<uint32_t>(r.MinimumTTL()));
   }

   template<>
   struct LoadImpl<rec_soa_t>
   {
      template<class InputIterator>
      static rec_soa_t impl(name_offset_tracker_t& tr, InputIterator& ii, InputIterator end)
      {
         rec_soa_t r{};

         r.MName(load_from<label_list_t>(tr, ii, end).Name());
         r.RName(load_from<label_list_t>(tr, ii, end).Name());
         r.Serial(load_from<uint32_t>(tr, ii, end));
         r.RefreshInterval(load_from<uint32_t>(tr, ii, end));
         r.RetryInterval(load_from<uint32_t>(tr, ii, end));
         r.ExpireInterval(load_from<uint32_t>(tr, ii, end));
         r.MinimumTTL(load_from<uint32_t>(tr, ii, end));

         return r;
      }
   };
}
