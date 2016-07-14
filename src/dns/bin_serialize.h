#pragma once

#include <ostream>
#include <string>

#include "dns/name_offset_tracker.h"

namespace dns
{
   template<class OutputIterator>
   void save_to(OutputIterator& o, name_offset_tracker_t& no_tr, uint8_t x)
   {
      *o++ = x;
      no_tr.increment_offset();
   }

   template<class OutputIterator>
   void save_to(OutputIterator& o, name_offset_tracker_t& no_tr, uint16_t x)
   {
      save_to(o, no_tr, static_cast<uint8_t>((x >> 8) & 0xFF));
      save_to(o, no_tr, static_cast<uint8_t>((x >> 0) & 0xFF));
   }
}
