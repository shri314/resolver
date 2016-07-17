#pragma once

#include "dns/rr_type.h"
#include "dns/rr_class.h"

#include "dns/name_offset_tracker.h"
#include "dns/label_list.h"

#include <ostream>
#include <string>
#include <limits>

namespace dns
{
   class record_t
   {
      public:
         void Name(const std::string& name)
         {
            m_name = name;
         }

         std::string Name() const
         {
            return m_name;
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

         void TTL(uint32_t v)
         {
            m_TTL = v;
         }

         uint32_t TTL() const
         {
            return m_TTL;
         }

         uint16_t DataLength() const
         {
            return static_cast<uint16_t>(m_record_data.size());
         }

         void Data(std::string record_data)
         {
            if(record_data.size() > std::numeric_limits<uint16_t>::max())
               record_data.erase(std::numeric_limits<uint16_t>::max());

            m_record_data = std::move(record_data);
         }

         std::string Data() const
         {
            return m_record_data;
         }

         template<class RecordT>
         RecordT RecordAs() const
         {
            return RecordT{};
         }

         friend std::ostream& operator<<(std::ostream& os, const record_t& rhs)
         {
            return os << "{ Name=" << rhs.Name() << ", Type=" << rhs.Type() << ", Class=" << rhs.Class() << ", TTL=" << rhs.TTL() << " }";
         }

      private:
         std::string m_name;
         rr_type_t m_type = rr_type_t::rec_a;
         rr_class_t m_class = rr_class_t::internet;
         int32_t m_TTL = 0;
         std::string m_record_data;
   };

   inline void save_to(name_offset_tracker_t& tr, const record_t& r)
   {
      save_to(tr, label_list_t{r.Name()});
      save_to(tr, static_cast<uint16_t>(r.Type()));
      save_to(tr, static_cast<uint16_t>(r.Class()));
      save_to(tr, r.TTL());
      save_to(tr, static_cast<uint16_t>(r.DataLength()));

      for(auto& c : r.Data())
         save_to(tr, static_cast<uint8_t>(c));
   }

   template<>
   struct LoadImpl<record_t>
   {
      template<class InputIterator>
      static record_t impl(name_offset_tracker_t& tr, InputIterator& ii, InputIterator end)
      {
         record_t r{};

         {
            r.Name(load_from<label_list_t>(tr, ii, end).Name());
            r.Type(static_cast<rr_type_t>(load_from<uint16_t>(tr, ii, end)));
            r.Class(static_cast<rr_class_t>(load_from<uint16_t>(tr, ii, end)));
            r.TTL(load_from<uint32_t>(tr, ii, end));
         }

         {
            std::string record_data;
            record_data.resize( load_from<uint16_t>(tr, ii, end) );

            for(auto& c : record_data)
               c = load_from<uint8_t>(tr, ii, end);

            r.Data(std::move(record_data));
         }

         return r;
      }
   };
}
