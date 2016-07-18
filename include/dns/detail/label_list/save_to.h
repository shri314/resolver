#pragma once

#include <ostream>
#include <string>

#include "dns/detail/label_list.h"
#include "dns/detail/name_offset_tracker.h"
#include "dns/detail/bin_serialize.h"
#include "dns/exception/bad_ptr_offset.h"
#include "dns/exception/bad_name.h"
#include "util/split2_at.h"

namespace dns
{
   inline void save_to(name_offset_tracker_t& tr, const label_list_t& ll)
   {
      auto&& range = ll.Name();

      while(!range.empty() && range.back() == '.')
         range.pop_back();

      while(true)
      {
         if(range.empty())
         {
            save_to(tr, static_cast<uint8_t>(0));
            break;
         }

         if(auto && p_offset = tr.find_offset(range))
         {
            if(*p_offset > 0x3FFF)
               throw exception::bad_ptr_offset("offset too long", 1);

            save_to(tr, static_cast<uint8_t>((*p_offset >> 8) | 0xC0));
            save_to(tr, static_cast<uint8_t>(*p_offset & 0xFF));
            break;
         }

         {
            tr.save_offset_of(range);

            auto&& split_parts = util::split2_at(range, '.');

            auto&& sz = split_parts.first.size();

            if(sz > 63)
               throw exception::bad_name("length too long", 1);

            if(sz == 0)
               throw exception::bad_name("wrong format", 1);

            save_to(tr, static_cast<uint8_t>(sz));

            for(auto x : split_parts.first)
            {
               save_to(tr, static_cast<uint8_t>(x));
            }

            range = std::move(split_parts.second);
         }
      }
   }
}
