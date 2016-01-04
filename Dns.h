#ifndef Dns_h__
#define Dns_h__

#include <string>
#include <array>
#include <vector>
#include <ostream>
#include <algorithm> // std::copy
#include <boost/asio/buffer.hpp>

namespace DnsProtocol
{
   struct Header
   {
      public:
         Header& ID(uint16_t v)
         {
            m_store[0] = (v >> 8) & 0xFF;
            m_store[1] = (v >> 0) & 0xFF;

            return *this;
         }

         uint16_t ID() const
         {
            return (uint16_t(m_store[0]) << 8)
                   | (uint16_t(m_store[1]) << 0);
         }

         //////////////

         Header& QR_Flag(bool v)
         {
            if(v)
               m_store[2] |= 0x80;
            else
               m_store[2] &= ~0x80;

            return *this;
         }

         bool QR_Flag() const
         {
            return (m_store[2] & 0x80) == 0x80;
         }

         Header& OpCode(uint16_t v)
         {
            m_store[2] |= (v & 0xF) << 3;
            m_store[2] &= ~((~v & 0xF) << 3);

            return *this;
         }

         uint16_t OpCode() const
         {
            return (m_store[2] >> 3) & 0xF;
         }

         Header& AA_Flag(bool v)
         {
            if(v)
               m_store[2] |= 0x04;
            else
               m_store[2] &= ~0x04;

            return *this;
         }

         bool AA_Flag() const
         {
            return (m_store[2] & 0x04) == 0x04;
         }

         Header& TC_Flag(bool v)
         {
            if(v)
               m_store[2] |= 0x02;
            else
               m_store[2] &= ~0x02;

            return *this;
         }

         bool TC_Flag() const
         {
            return (m_store[2] & 0x02) == 0x02;
         }

         Header& RD_Flag(bool v)
         {
            if(v)
               m_store[2] |= 0x01;
            else
               m_store[2] &= ~0x01;

            return *this;
         }

         bool RD_Flag() const
         {
            return m_store[2] & 0x01 == 0x01;
         }

         //////////////

         Header& RA_Flag(bool v)
         {
            if(v)
               m_store[3] |= 0x80;
            else
               m_store[3] &= ~0x80;

            return *this;
         }

         bool RA_Flag() const
         {
            return (m_store[3] & 0x80) == 0x80;
         }

         Header& ZCode(uint16_t v)
         {
            m_store[3] |= (v & 0x7) << 4;
            m_store[3] &= ~((~v & 0x7) << 4);

            return *this;
         }

         uint16_t ZCode()
         {
            return (m_store[3] >> 4) & 0x7;
         }

         Header& RCode(uint16_t v)
         {
            m_store[3] |= (v & 0xF);
            m_store[3] &= ~(~v & 0xF);

            return *this;
         }

         uint16_t RCode() const
         {
            return (m_store[3] & 0xF);
         }

         /////////////

         Header& QdCount(uint16_t v)
         {
            m_store[4] = (v >> 8) & 0xFF;
            m_store[5] = (v >> 0) & 0xFF;

            return *this;
         }

         uint16_t QdCount() const
         {
            return (uint16_t(m_store[4]) << 8)
                   | (uint16_t(m_store[5]) << 0);
         }

         Header& AnCount(uint16_t v)
         {
            m_store[6] = (v >> 8) & 0xFF;
            m_store[7] = (v >> 0) & 0xFF;

            return *this;
         }

         uint16_t AnCount() const
         {
            return (uint16_t(m_store[6]) << 8)
                   | (uint16_t(m_store[7]) << 0);
         }

         Header& NsCount(uint16_t v)
         {
            m_store[8] = (v >> 8) & 0xFF;
            m_store[9] = (v >> 0) & 0xFF;

            return *this;
         }

         uint16_t NsCount() const
         {
            return (uint16_t(m_store[8]) << 8)
                   | (uint16_t(m_store[9]) << 0);
         }

         Header& ArCount(uint16_t v)
         {
            m_store[10] = (v >> 8) & 0xFF;
            m_store[11] = (v >> 0) & 0xFF;

            return *this;
         }

         uint16_t ArCount() const
         {
            return (uint16_t(m_store[10]) << 8)
                   | (uint16_t(m_store[11]) << 0);
         }

         auto Save(std::vector<boost::asio::const_buffer>& buf) const
         {
            buf.push_back( boost::asio::const_buffer{&m_store[0], m_store.size()} );
         }

         auto Save(std::vector<uint8_t>& buf) const
         {
            std::copy( m_store.begin(), m_store.end(), std::back_inserter(buf) );
         }

         auto Save() const
         {
            std::vector<uint8_t> buf;
            Save(buf);
            return buf;
         }

         Header()
         {
            ZCode(0);
         }

         template<class Iter>
         Header(const std::pair<Iter, Iter>& wd)
         {
            std::copy(
                  wd.first,
                  wd.second - wd.first > m_store.size() ? wd.first + m_store.size() : wd.second,
                  m_store.begin()
               );
         }

      private:
         std::array<uint8_t, 12> m_store;
   };

   struct bad_name : public std::exception
   {
   public:
      bad_name(const char* const str)
         : m_str(str)
      {
      }

      bad_name(bad_name& rhs)
         : m_str( rhs.m_str )
      {
      }

      bad_name(bad_name&& rhs)
         : m_str( rhs.m_str )
      {
      }

      const char* what() const noexcept { return m_str; }

      void operator=(const bad_name&) = delete;
      void operator=(bad_name&&) = delete;

   private:
      const char* const m_str;
   };

   struct QualifiedName
   {
      public:
         QualifiedName()
         {
            m_store.resize(1);
         }

         template<class Iter>
         QualifiedName& Set(Iter begin, Iter end)
         {
            m_store.clear();
            m_store.reserve( end - begin + 1 );

            while(true)
            {
               auto pos = std::find(begin, end, '.');

               auto sz = pos - begin;

               if(sz == 0)
                  break;

               if(sz > 63)
               {
                  throw bad_name("length too long");
               }

               m_store.push_back(sz);

               std::copy( begin, pos, std::back_inserter(m_store) );

               begin = (pos == end) ? pos : (pos + 1);

               if(begin == end)
                  break;
            }

            if(begin == end)
               m_store.push_back(0);
            else
               throw bad_name("wrong format");

            return *this;
         }

         QualifiedName& Set(const std::string& qname)
         {
            return Set(qname.begin(), qname.end());
         }

         std::string Get() const
         {
            std::string str;
            std::string sep;

            unsigned c = 0;
            for(auto x : m_store)
            {
               if(c == 0)
               {
                  c = (unsigned)x;

                  if(c != 0)
                     str += sep;
               }
               else
               {
                  --c;

                  sep = ".";

                  str += (unsigned char)x;
               }
            }

            return str;
         }

         auto Save(std::vector<boost::asio::const_buffer>& buf) const
         {
            buf.push_back( boost::asio::const_buffer{&m_store[0], m_store.size()} );
         }

         auto Save(std::vector<uint8_t>& buf) const
         {
            std::copy( m_store.begin(), m_store.end(), std::back_inserter(buf) );
         }

         auto Save() const
         {
            std::vector<uint8_t> buf;
            Save(buf);
            return buf;
         }

         /*
         template<class Iter>
         std::pair<Iter, Iter> Load(const std::pair<Iter, Iter>& wd)
         {
            std::copy( wd.first, wd.second, std::back_inserter(m_store) );

            return make_pair( wd.second, wd.second );
         }
         */

         friend std::ostream& operator<<(std::ostream& os, const QualifiedName& rhs)
         {
            unsigned c = 0;
            for(auto x : rhs.m_store)
            {
               if(c == 0)
               {
                  c = (unsigned)x;
                  os << "[" << c << "]";
               }
               else
               {
                  --c;
                  os << (unsigned char)x;
               }
            }

            return os;
         }

      private:
         std::vector<uint8_t> m_store;
   };

   struct Question
   {
      public:
         Question()
         {
         }

         Question& QName(const std::string& qname)
         {
            m_qname.Set(qname);

            return *this;
         }

         std::string QName() const
         {
            return m_qname.Get();
         }

         Question& QType(uint16_t v)
         {
            m_store[0] = (v >> 8) & 0xFF;
            m_store[1] = (v >> 0) & 0xFF;

            return *this;
         }

         uint16_t QType() const
         {
            return (uint16_t(m_store[0]) << 8) |
                   (uint16_t(m_store[1]) << 0);
         }

         Question& QClass(uint16_t v)
         {
            m_store[2] = (v >> 8) & 0xFF;
            m_store[3] = (v >> 0) & 0xFF;

            return *this;
         }

         uint16_t QClass() const
         {
            return (uint16_t(m_store[2]) << 8) |
                   (uint16_t(m_store[3]) << 0);
         }

         auto Save(std::vector<boost::asio::const_buffer>& buf) const
         {
            m_qname.Save(buf);
            buf.push_back( boost::asio::const_buffer{&m_store[0], m_store.size()} );
         }

         auto Save(std::vector<uint8_t>& buf) const
         {
            m_qname.Save(buf);
            std::copy( m_store.begin(), m_store.end(), std::back_inserter(buf) );
         }

         auto Save() const
         {
            std::vector<uint8_t> buf;
            Save(buf);
            return buf;
         }

         /*
         template<class Iter>
         std::pair<Iter, Iter> Load(const std::pair<Iter, Iter>& wd)
         {
            auto&& wdremaining = m_qname.Save(wd);

            std::copy( wdremaining.first, wdremaining.second, std::back_inserter(m_store) );
         }
         */

      private:
         QualifiedName m_qname;
         std::array<uint8_t, 4> m_store;
   };
};

#endif
