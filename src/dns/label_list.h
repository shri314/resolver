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
      std::string buffer;
      buffer.reserve(256);

      uint8_t rem_labelchars = 0;
      bool term_found = false;
      std::experimental::optional<uint16_t> ptr_offset;

      while(i != end && !term_found)
      {
         uint8_t x;
         load_from(tr, i, end, x);

         if(ptr_offset)
         {
            *ptr_offset |= static_cast<uint16_t>(x); // accumulate the second byte into ptr_offset LSB

            if(!buffer.empty())
               buffer.push_back('.');

            if( auto&& f = tr.find_name( *ptr_offset ) )
               buffer.append( *f );
            else
               throw dns::exception::bad_data_stream("unseen offset", 1);

            term_found = true;
         }
         else if(rem_labelchars == 0)
         {
            uint8_t cx = static_cast<uint8_t>(x); // usually is the size of label, or null, or ptr_offset byte

            if(cx == 0)
            {
               term_found = true;
            }
            else if(cx > 63)
            {
               if((cx & 0xC0) == 0xC0)
                  ptr_offset = static_cast<uint16_t>(x << 8); // accumulate the first byte into ptr_offset MSB
               else
                  throw dns::exception::bad_data_stream("length too long", 2);
            }
            else
            {
               if(!buffer.empty())
                  buffer.push_back('.');

               rem_labelchars = cx;
            }
         }
         else
         {
            buffer.push_back(x);
            --rem_labelchars;
         }
      }

      if(!term_found)
         throw dns::exception::bad_data_stream("truncated", 2);

      ll.Name(buffer);
   }
}
