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
         void ID(uint16_t v)
         {
            m_store[0] = (v >> 8) & 0xFF;
            m_store[1] = (v >> 0) & 0xFF;
         }

         uint16_t ID() const
         {
            return (uint16_t(m_store[0]) << 8)
                   | (uint16_t(m_store[1]) << 0);
         }

         //////////////

         Header& QR_Flag(bool v)
         {
            m_store[2] |= (v ? 0x80 : 0x00);

            return *this;
         }

         bool QR_Flag() const
         {
            return (m_store[2] & 0x80) == 0x80;
         }

         Header& OpCode(uint16_t v)
         {
            m_store[2] |= (v & 0xF) << 3;

            return *this;
         }

         uint16_t OpCode() const
         {
            return (m_store[2] >> 3) & 0xF;
         }

         Header& AA_Flag(bool v)
         {
            m_store[2] |= (v ? 0x04 : 0x00);

            return *this;
         }

         bool AA_Flag() const
         {
            return (m_store[2] & 0x04) == 0x04;
         }

         Header& TC_Flag(bool v)
         {
            m_store[2] |= (v ? 0x02 : 0x00);

            return *this;
         }

         bool TC_Flag() const
         {
            return (m_store[2] & 0x02) == 0x02;
         }

         Header& RD_Flag(bool v)
         {
            m_store[2] |= (v ? 0x01 : 0x00);

            return *this;
         }

         bool RD_Flag() const
         {
            return m_store[2] & 0x01 == 0x01;
         }

         //////////////

         Header& RA_Flag(bool v)
         {
            m_store[3] |= (v ? 0x80 : 0x00);

            return *this;
         }

         bool RA_Flag() const
         {
            return (m_store[3] & 0x80) == 0x80;
         }

         Header& ZCode(uint16_t v)
         {
            m_store[3] |= (v & 0x7) << 4;

            return *this;
         }

         uint16_t ZCode()
         {
            return (m_store[3] >> 4) & 0x7;
         }

         Header& RCode(uint16_t v)
         {
            m_store[3] |= (v & 0xF);

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

         auto WireData(std::vector<boost::asio::const_buffer>& buf) const
         {
            buf.push_back( boost::asio::const_buffer{&m_store[0], m_store.size()} );
         }

         auto WireData(std::vector<uint8_t>& buf) const
         {
            std::copy( m_store.begin(), m_store.end(), std::back_inserter(buf) );
         }

         auto WireData() const
         {
            std::vector<uint8_t> buf;
            WireData(buf);
            return buf;
         }

         Header()
         {
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

   struct QualifiedName
   {
      public:
         QualifiedName()
         {
            m_store.resize(1);
         }

         template<class Iter>
         QualifiedName(const std::pair<Iter, Iter>& wd)
         {
            std::copy( wd.first, wd.second, std::back_inserter(m_store) );
         }

         QualifiedName& Set(const std::string& qname)
         {
            m_store.clear();
            m_store.reserve(qname.size() + 1);

            auto pos = qname.size();
            pos = 0;

            while(true)
            {
               auto dotpos = qname.find('.', pos);

               auto endpos = (dotpos == qname.npos) ? qname.size() : dotpos;

               uint8_t sz = (endpos - pos) > 255 ? 255 : (endpos - pos);

               m_store.push_back(sz);

               std::copy(qname.data() + pos, qname.data() + pos + sz, std::back_inserter(m_store));

               if(dotpos == qname.npos)
                  break;

               pos = dotpos + 1;
            }

            m_store.push_back(0);

            return *this;
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

         auto WireData(std::vector<boost::asio::const_buffer>& buf) const
         {
            buf.push_back( boost::asio::const_buffer{&m_store[0], m_store.size()} );
         }

         auto WireData(std::vector<uint8_t>& buf) const
         {
            std::copy( m_store.begin(), m_store.end(), std::back_inserter(buf) );
         }

         auto WireData() const
         {
            std::vector<uint8_t> buf;
            WireData(buf);
            return buf;
         }

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

         auto WireData(std::vector<boost::asio::const_buffer>& buf) const
         {
            m_qname.WireData(buf);
            buf.push_back( boost::asio::const_buffer{&m_store[0], m_store.size()} );
         }

         auto WireData(std::vector<uint8_t>& buf) const
         {
            m_qname.WireData(buf);
            std::copy( m_store.begin(), m_store.end(), std::back_inserter(buf) );
         }

         auto WireData() const
         {
            std::vector<uint8_t> buf;
            WireData(buf);
            return buf;
         }

      private:
         QualifiedName m_qname;
         std::array<uint8_t, 4> m_store;
   };
};

#endif
