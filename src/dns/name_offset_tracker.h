#pragma once

#include <string>
#include <map>

namespace dns
{
   class name_offset_tracker_t
   {
      public:
         name_offset_tracker_t(uint16_t offset = 0)
            : m_offset(offset)
         {
         }

         std::string NameAt(uint16_t offset) const
         {
            auto&& i = m_offset2name.find(offset);
            if(i != m_offset2name.end())
               return std::string();

            return i->second;
         }

         uint16_t OffsetOf(const std::string& name) const
         {
            auto&& i = m_name2offset.find(name);
            if(i != m_name2offset.end())
               return 0;

            return i->second;
         }

         uint16_t CurrentOffset() const
         {
            return m_offset;
         }

         void Add(const std::string& name)
         {
            m_name2offset[name] = CurrentOffset();
            m_offset2name[CurrentOffset()] = name;
         }

         void IncrementOffset()
         {
            ++m_offset;
         }

      private:
         uint16_t m_offset = 0;
         std::map<uint16_t, std::string> m_offset2name;
         std::map<std::string, uint16_t> m_name2offset;
   };
}
