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

   template<class InputIterator>
   void load_from(name_offset_tracker_t& tr, InputIterator& i, InputIterator end, label_list_t& ll)
   {
      auto&& term_found = false;
      auto&& rem_labelchars = uint8_t{0};
      auto&& ptr_offset = std::experimental::optional<uint16_t> {};
      auto&& name_parts = std::vector<std::pair<uint16_t, std::string>> {};

      while(i != end && !term_found)
      {
         if(ptr_offset)
         {
            // CASE I: read and accumulate the second byte into ptr_offset LSB

            uint8_t of;
            load_from(tr, i, end, of);

            *ptr_offset |= static_cast<uint16_t>(of);

            if(auto && f = tr.find_name(*ptr_offset))
            {
               name_parts.emplace_back( *ptr_offset, *f );
               term_found = true;
            }
            else
               throw dns::exception::bad_data_stream("unseen offset", 1);
         }
         else if(rem_labelchars == 0)
         {
            // CASE II: expected is a number that is the size of label, or null, or ptr_offset byte

            uint8_t sz;
            load_from(tr, i, end, sz);

            if(sz == 0)
            {
               term_found = true;
            }
            else if(sz > 63)
            {
               if((sz & 0xC0) == 0xC0)
                  ptr_offset = static_cast<uint16_t>((sz & ~0xC0) << 8); // accumulate the first byte into ptr_offset MSB
               else
                  throw dns::exception::bad_data_stream("length too long", 2);
            }
            else
            {
               name_parts.emplace_back( tr.current_offset() - 1, "" );
               name_parts.back().second.reserve(sz);
               rem_labelchars = sz;
            }
         }
         else
         {
            // CASE III: expected is a set of characters of a namepart (rem_labelchars chars long)

            uint8_t ch;
            load_from(tr, i, end, ch);

            name_parts.back().second.push_back(ch);
            --rem_labelchars;
         }
      }

      if(!term_found)
         throw dns::exception::bad_data_stream("truncated", 2);

      std::string last_entry;
      std::for_each( name_parts.rbegin(), name_parts.rend(), [&last_entry, &tr](auto& entry) {
         last_entry = entry.second += (last_entry.empty() ? "" : ".") + last_entry;
         tr.insert( entry.first, entry.second );
      });

      ll.Name(last_entry);
   }
}
