#pragma once

#include "vector_end_range.h"

#include "bad_name.h"
#include "bad_data_stream.h"
#include "bad_ptr_offset.h"

#include <boost/asio/buffer.hpp>

#include <vector>
#include <string>
#include <ostream>
#include <algorithm> // std::copy

namespace DnsProtocol
{
   struct LabelList_t
   {
      public:
         explicit LabelList_t(std::vector<uint8_t>& store, const std::string& qname = "", uint16_t ptr_offset = 0)
            : m_store(store)
         {
            Set(qname, ptr_offset);
         }

         template<class Iter>
         void Load(Iter& begin, Iter end)
         {
            std::vector<uint8_t> t_store;

            t_store.clear();
            t_store.reserve(256);

            uint8_t rem_labelchars = 0;
            bool term_found = false;
            bool ptr_found = false;

            for(; begin != end && !term_found; ++begin)
            {
               auto x = *begin;

               if(t_store.size() + 2 > 256)
                  throw bad_data_stream("length too long", 1);

               t_store.push_back(static_cast<uint8_t>(x));

               if(ptr_found)
               {
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
                        ptr_found = true;
                     else
                        throw bad_data_stream("length too long", 2);
                  }
                  else
                  {
                     rem_labelchars = cx;
                  }
               }
               else
               {
                  --rem_labelchars;
               }
            }

            if(!term_found)
               throw bad_data_stream("truncated", 2);

            m_store.assign(t_store.begin(), t_store.end());
         }

         LabelList_t& Set(const std::string& qname, uint16_t ptr_offset = 0)
         {
            if(ptr_offset > 0x3FFF)
               throw bad_ptr_offset("offset too long", 1);

            auto begin = qname.begin();
            auto end = qname.end();
            auto term_space = ptr_offset > 0 ? 2 : 1;

            std::vector<uint8_t> t_store;

            t_store.clear();
            t_store.reserve(std::min(static_cast<int>(std::distance(begin, end) + term_space), 256));

            while(true)
            {
               auto pos = std::find(begin, end, '.');

               auto sz = pos - begin;

               if(sz > 63)
                  throw bad_name("length too long", 1);

               if(t_store.size() + sz + term_space >= 256)
                  throw bad_name("length too long", 2);

               if(sz == 0) // we seem to have hit the end
               {
                  if(begin != end)
                     throw bad_name("wrong format", 1);
                  else
                     break;
               }
               else
               {
                  t_store.push_back(sz); // non zero size

                  std::copy(begin, pos, std::back_inserter(t_store));

                  begin = (pos == end) ? pos : (pos + 1);

                  if(begin == end)
                     break;
               }
            }

            {
               // put the null terminator or the end ptr

               if(t_store.size() + term_space >= 256)
                  throw bad_name("length too long", 3);

               if(ptr_offset > 0)
               {
                  t_store.push_back(static_cast<uint8_t>(ptr_offset >> 8) | 0xC0);
                  t_store.push_back(static_cast<uint8_t>(ptr_offset & 0xFF));
               }
               else
               {
                  t_store.push_back(0);
               }
            }

            m_store.assign(t_store.begin(), t_store.end());

            return *this;
         }

         std::pair<std::string, uint16_t> Get(uint16_t start_offset = 0) const
         {
            std::string str;

            uint16_t ptr_offset = 0;
            uint8_t rem_labelchars = 0;

            for(auto x : m_store)
            {
               if(ptr_offset)
               {
                  ptr_offset |= static_cast<uint16_t>(x); // accumulate the second byte into ptr_offset LSB
               }
               else if(rem_labelchars == 0)
               {
                  uint8_t cx = static_cast<uint8_t>(x);

                  if((cx & 0xC0) == 0xC0) // found ptr_offset (first byte)
                  {
                     ptr_offset = static_cast<uint16_t>(x) << 8; // accumulate the first byte into ptr_offset MSB
                  }
                  else if(cx != 0)        // found non-zero label
                  {
                     rem_labelchars = cx;

                     if(!str.empty())
                        if(start_offset <= 0)
                           str += ".";
                  }
               }
               else
               {
                  --rem_labelchars;

                  if(start_offset <= 0)
                     str += static_cast<unsigned char>(x); // label char
               }

               if(start_offset > 0)
                  --start_offset;
            }

            return std::make_pair(str, ptr_offset & 0x3FFF);
         }

         void Save(std::vector<boost::asio::const_buffer>& buf) const
         {
            buf.push_back(boost::asio::const_buffer{&m_store[0], m_store.size()});
         }

         void Save(std::vector<uint8_t>& buf) const
         {
            std::copy(m_store.begin(), m_store.end(), std::back_inserter(buf));
         }

         auto Save() const
         {
            std::vector<uint8_t> buf;
            Save(buf);
            return buf;
         }

         friend std::ostream& operator<<(std::ostream& os, const LabelList_t& rhs)
         {
            auto&& res = rhs.Get();

            os << "[" << res.first << "]";

            if(res.second)
               os << "->[" << res.second << "]";

            return os;
         }

         uint16_t Size() const
         {
            return m_store.size();
         }

      private:
         detail::vector_end_range m_store;
   };
}
