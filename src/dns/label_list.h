#pragma once

#include <ostream>
#include <string>

#include "dns/name_offset_tracker.h"
#include "dns/exception/bad_data_stream.h"
#include "dns/exception/bad_ptr_offset.h"
#include "dns/exception/bad_name.h"
#include "dns/bin_serialize.h"
#include "split2_at.h"

namespace dns
{
   class label_list_t
   {
      public:
         label_list_t(std::string name = "")
         {
            Name(std::move(name));
         }

         void Name(std::string name)
         {
            m_name = std::move(name);
         }

         std::string Name() const
         {
            return m_name;
         }

         friend std::ostream& operator<<(std::ostream& os, const label_list_t& rhs)
         {
            return os << "[" << rhs.Name() << "]";
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
         std::string m_name;
   };

   template<class OutputIterator>
   void save_to(name_offset_tracker_t& tr, OutputIterator& o, const label_list_t& ll)
   {
      auto&& range = ll.Name();

      while(!range.empty() && range.back() == '.')
         range.pop_back();

      while(true)
      {
         if(range.empty())
         {
            save_to(tr, o, static_cast<uint8_t>(0));
            break;
         }

         if(auto && p_offset = tr.find_offset(range))
         {
            if(*p_offset > 0x3FFF)
               throw exception::bad_ptr_offset("offset too long", 1);

            save_to(tr, o, static_cast<uint8_t>((*p_offset >> 8) | 0xC0));
            save_to(tr, o, static_cast<uint8_t>(*p_offset & 0xFF));
            break;
         }
      
         {
            tr.save_offset_of(range);

            auto&& split_parts = split2_at(range, '.');

            auto&& sz = split_parts.first.size();

            if(sz > 63)
               throw exception::bad_name("length too long", 1);

            if(sz == 0)
               throw exception::bad_name("wrong format", 1);

            save_to(tr, o, static_cast<uint8_t>(sz));

            for(auto x : split_parts.first)
            {
               save_to(tr, o, static_cast<uint8_t>(x));
            }

            range = std::move(split_parts.second);
         }
      }
   }
}
