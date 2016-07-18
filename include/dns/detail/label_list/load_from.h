#pragma once

#include <ostream>
#include <string>

#include "dns/detail/name_offset_tracker.h"
#include "dns/detail/bin_serialize.h"
#include "dns/detail/label_list.h"
#include "dns/detail/label_list/save_to.h"
#include "dns/detail/label_list/load_from.h"
#include "dns/exception/bad_data_stream.h"

#include "util/name_builder.h"

namespace dns
{
   template<>
   struct LoadImpl<label_list_t>
   {
      template<class InputIterator>
      static label_list_t impl(name_offset_tracker_t& tr, InputIterator& ii, InputIterator end)
      {
         auto&& term_found = false;
         auto&& rem_labelchars = uint8_t{0};
         auto&& ptr_offset = std::experimental::optional<uint16_t> {};
         auto&& nb = util::name_builder{'.'};

         while(ii != end && !term_found)
         {
            if(ptr_offset)
            {
               // CASE I: read and accumulate the second byte into ptr_offset LSB

               uint8_t of = load_from<uint8_t>(tr, ii, end);

               *ptr_offset |= static_cast<uint16_t>(of);

               if( auto&& temp_tr = tr.slice(*ptr_offset) )
               {
                  try
                  {
                     auto&& temp_bi = temp_tr->cbegin();
                     auto&& temp_end = temp_tr->cend();
                     auto&& temp_n = load_from<label_list_t>( *temp_tr, temp_bi, temp_end ).Name();

                     nb.add_part(temp_n);

                     term_found = true;
                  }
                  catch(const std::exception& e)
                  {
                     // FIXME - nest exception
                  }
               }

               if(!term_found)
                  throw dns::exception::bad_data_stream("bad offset", 1);
            }
            else if(rem_labelchars == 0)
            {
               // CASE II: expected is a number that is the size of label, or null, or ptr_offset byte

               uint8_t sz = load_from<uint8_t>(tr, ii, end);

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
                  nb.add_part("");

                  rem_labelchars = sz;
               }
            }
            else
            {
               // CASE III: expected is a set of characters of a namepart (rem_labelchars chars long)

               nb.append( load_from<uint8_t>(tr, ii, end) );

               --rem_labelchars;
            }
         }

         if(!term_found)
            throw dns::exception::bad_data_stream("truncated", 2);

         return label_list_t{ std::move(nb).full_name() };
      }
   };
}
