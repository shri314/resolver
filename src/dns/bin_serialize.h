#pragma once

#include <ostream>
#include <string>

#include "dns/name_offset_tracker.h"
#include "dns/exception/bad_data_stream.h"

namespace dns
{
   template<class OutputIterator>
   void save_to(name_offset_tracker_t& tr, OutputIterator& o, uint8_t x)
   {
      *o++ = x;
      tr.increment_offset();
   }

   template<class OutputIterator>
   void save_to(name_offset_tracker_t& tr, OutputIterator& o, uint16_t x)
   {
      save_to(tr, o, static_cast<uint8_t>((x >> 8) & 0xFF));
      save_to(tr, o, static_cast<uint8_t>((x >> 0) & 0xFF));
   }

   template<class OutputIterator>
   void save_to(name_offset_tracker_t& tr, OutputIterator& o, uint32_t x)
   {
      save_to(tr, o, static_cast<uint8_t>((x >> 24) & 0xFF));
      save_to(tr, o, static_cast<uint8_t>((x >> 16) & 0xFF));
      save_to(tr, o, static_cast<uint8_t>((x >> 8) & 0xFF));
      save_to(tr, o, static_cast<uint8_t>((x >> 0) & 0xFF));
   }

   template<class InputIterator>
   void load_from(name_offset_tracker_t& tr, InputIterator& i, InputIterator end, uint8_t& x)
   {
      if(i != end)
      {
         x = static_cast<uint8_t>(*i++);
         tr.increment_offset();
      }
      else
         throw dns::exception::bad_data_stream("truncated", 1);
   }

   template<class InputIterator>
   void load_from(name_offset_tracker_t& tr, InputIterator& i, InputIterator end, uint16_t& x)
   {
      uint8_t x1;
      load_from(tr, i, end, x1);

      uint8_t x2;
      load_from(tr, i, end, x2);

      x = (static_cast<uint16_t>(x1) << 8) |
          (static_cast<uint16_t>(x2));
   }

   template<class InputIterator>
   void load_from(name_offset_tracker_t& tr, InputIterator& i, InputIterator end, uint32_t& x)
   {
      uint8_t x1;
      load_from(tr, i, end, x1);

      uint8_t x2;
      load_from(tr, i, end, x2);

      uint8_t x3;
      load_from(tr, i, end, x3);

      uint8_t x4;
      load_from(tr, i, end, x4);

      x = (static_cast<uint16_t>(x1) << 24) |
          (static_cast<uint16_t>(x2) << 16) |
          (static_cast<uint16_t>(x3) << 8) |
          (static_cast<uint16_t>(x4));
   }
}
