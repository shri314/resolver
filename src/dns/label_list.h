#pragma once

#include <ostream>
#include <string>

#include "dns/name_offset_tracker.h"
#include "dns/exception/bad_data_stream.h"
#include "dns/exception/bad_ptr_offset.h"
#include "dns/exception/bad_name.h"
#include "dns/bin_serialize.h"

namespace dns
{
   class label_list_t
   {
      public:
         label_list_t(const std::string& name = "")
            : m_name(name)
         {
         }

         void Name(const std::string& name)
         {
            m_name = name;
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
   void save_to(OutputIterator& o, name_offset_tracker_t& no_tr, const label_list_t& ll)
   {
      auto&& name = ll.Name();
      auto&& begin = name.begin();
      auto&& end = name.end();
      auto&& start_offset = no_tr.CurrentOffset();

      while(true)
      {
         auto&& sub_name = std::string(begin, end);
         auto&& ptr_offset = no_tr.OffsetOf(sub_name);

         if(ptr_offset > 0x3FFF)
            throw exception::bad_ptr_offset("offset too long", 1);

         auto term_space = ptr_offset > 0 ? 2 : 1;

         auto pos = std::find(begin, end, '.');

         auto sz = pos - begin;

         if(sz > 63)
            throw exception::bad_name("length too long", 1);

         if(no_tr.CurrentOffset() - start_offset + sz + term_space >= 256)
            throw exception::bad_name("length too long", 2);

         if(sz == 0) // we seem to have hit the end
         {
            if(begin != end)
               throw exception::bad_name("wrong format", 1);
            else
               break;
         }
         else
         {
            if(ptr_offset == 0)
               no_tr.Add(sub_name);

            save_to(o, no_tr, static_cast<uint8_t>(sz));

            std::for_each(begin, pos, [&o, &no_tr](uint8_t x)
            {
               save_to(o, no_tr, x);
            });

            begin = (pos == end) ? end : (pos + 1);

            if(begin == end)
               break;
         }
      }

      {
         // put the null terminator or the end ptr

         if(no_tr.CurrentOffset() - start_offset + term_space >= 256)
            throw exception::bad_name("length too long", 3);

         if(ptr_offset > 0)
         {
            save_to(o, no_tr, static_cast<uint8_t>((ptr_offset >> 8) | 0xC0));
            save_to(o, no_tr, static_cast<uint8_t>(ptr_offset & 0xFF));
         }
         else
         {
            save_to(o, no_tr, static_cast<uint8_t>(0));
         }
      }
   }
}
