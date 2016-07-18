#pragma once

#include <ostream>
#include <string>

#include "dns/detail/name_offset_tracker.h"
#include "dns/exception/bad_data_stream.h"

namespace dns
{
   void save_to(name_offset_tracker_t& tr, uint8_t x)
   {
      tr.save(x);
   }

   void save_to(name_offset_tracker_t& tr, uint16_t x)
   {
      save_to(tr, static_cast<uint8_t>((x >> 8) & 0xFF));
      save_to(tr, static_cast<uint8_t>((x >> 0) & 0xFF));
   }

   void save_to(name_offset_tracker_t& tr, uint32_t x)
   {
      save_to(tr, static_cast<uint8_t>((x >> 24) & 0xFF));
      save_to(tr, static_cast<uint8_t>((x >> 16) & 0xFF));
      save_to(tr, static_cast<uint8_t>((x >> 8) & 0xFF));
      save_to(tr, static_cast<uint8_t>((x >> 0) & 0xFF));
   }

   template<class T>
   struct LoadImpl;

   template<class T, class InputIterator>
   T load_from(name_offset_tracker_t& tr, InputIterator& ii, InputIterator end)
   {
      return LoadImpl<T>::impl(tr, ii, end);
   }

   template<>
   struct LoadImpl<uint8_t>
   {
      template<class InputIterator>
      static uint8_t impl(name_offset_tracker_t& tr, InputIterator& ii, InputIterator end)
      {
         if(ii != end)
         {
            return tr.save(static_cast<uint8_t>(*ii++));
         }
         else
            throw dns::exception::bad_data_stream("truncated", 1);
      }
   };

   template<>
   struct LoadImpl<uint16_t>
   {
      template<class InputIterator>
      static uint16_t impl(name_offset_tracker_t& tr, InputIterator& ii, InputIterator end)
      {
         uint8_t x1 = load_from<uint8_t>(tr, ii, end);
         uint8_t x2 = load_from<uint8_t>(tr, ii, end);

         return (static_cast<uint16_t>(x1) << 8) |
                (static_cast<uint16_t>(x2));
      }
   };

   template<>
   struct LoadImpl<uint32_t>
   {
      template<class InputIterator>
      static uint32_t impl(name_offset_tracker_t& tr, InputIterator& ii, InputIterator end)
      {
         uint8_t x1 = load_from<uint8_t>(tr, ii, end);
         uint8_t x2 = load_from<uint8_t>(tr, ii, end);
         uint8_t x3 = load_from<uint8_t>(tr, ii, end);
         uint8_t x4 = load_from<uint8_t>(tr, ii, end);

         return (static_cast<uint16_t>(x1) << 24) |
                (static_cast<uint16_t>(x2) << 16) |
                (static_cast<uint16_t>(x3) << 8) |
                (static_cast<uint16_t>(x4));
      }
   };
}
