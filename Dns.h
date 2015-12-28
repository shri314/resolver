#ifndef Dns_h__
#define Dns_h__

#include <string>
#include <array>
#include <vector>
#include <ostream>
#include <algorithm> // std::copy

namespace DnsProtocol
{
   struct HeaderPod
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

         void QR_Flag(bool v)
         {
            m_store[2] |= (v ? 0x80 : 0x00);
         }

         bool QR_Flag() const
         {
            return (m_store[2] & 0x80) == 0x80;
         }

         void OpCode(uint16_t v)
         {
            m_store[2] |= (v & 0xF) << 3;
         }

         uint16_t OpCode() const
         {
            return (m_store[2] >> 3) & 0xF;
         }

         void AA_Flag(bool v)
         {
            m_store[2] |= (v ? 0x04 : 0x00);
         }

         bool AA_Flag() const
         {
            return (m_store[2] & 0x04) == 0x04;
         }

         void TC_Flag(bool v)
         {
            m_store[2] |= (v ? 0x02 : 0x00);
         }

         bool TC_Flag() const
         {
            return (m_store[2] & 0x02) == 0x02;
         }

         void RD_Flag(bool v)
         {
            m_store[2] |= (v ? 0x01 : 0x00);
         }

         bool RD_Flag() const
         {
            return m_store[2] & 0x01 == 0x01;
         }

         //////////////

         void RA_Flag(bool v)
         {
            m_store[3] |= (v ? 0x80 : 0x00);
         }

         bool RA_Flag() const
         {
            return (m_store[3] & 0x80) == 0x80;
         }

         void ZCode(uint16_t v)
         {
            m_store[3] |= (v & 0x7) << 4;
         }

         uint16_t ZCode()
         {
            return (m_store[3] >> 4) & 0x7;
         }

         void RCode(uint16_t v)
         {
            m_store[3] |= (v & 0xF);
         }

         uint16_t RCode() const
         {
            return (m_store[3] & 0xF);
         }

         /////////////

         void QdCount(uint16_t v)
         {
            m_store[4] = (v >> 8) & 0xFF;
            m_store[5] = (v >> 0) & 0xFF;
         }

         uint16_t QdCount() const
         {
            return (uint16_t(m_store[4]) << 8)
                   | (uint16_t(m_store[5]) << 0);
         }

         void AnCount(uint16_t v)
         {
            m_store[6] = (v >> 8) & 0xFF;
            m_store[7] = (v >> 0) & 0xFF;
         }

         uint16_t AnCount() const
         {
            return (uint16_t(m_store[6]) << 8)
                   | (uint16_t(m_store[7]) << 0);
         }

         void NsCount(uint16_t v)
         {
            m_store[8] = (v >> 8) & 0xFF;
            m_store[9] = (v >> 0) & 0xFF;
         }

         uint16_t NsCount() const
         {
            return (uint16_t(m_store[8]) << 8)
                   | (uint16_t(m_store[9]) << 0);
         }

         void ArCount(uint16_t v)
         {
            m_store[10] = (v >> 8) & 0xFF;
            m_store[11] = (v >> 0) & 0xFF;
         }

         uint16_t ArCount() const
         {
            return (uint16_t(m_store[10]) << 8)
                   | (uint16_t(m_store[11]) << 0);
         }

         auto WireData() const
         {
            return std::make_pair(m_store.cbegin(), m_store.cend());
         }

         void WireData(std::vector<uint8_t>& store)&&
         {
            std::move(m_store.begin(), m_store.end(), std::back_inserter(store));
         }

         HeaderPod()
         {
            m_store.resize(12);
         }

         template<class Iter>
         HeaderPod(const std::pair<Iter, Iter>& wd)
         {
            m_store.resize(12);

            std::copy(
                  wd.first,
                  wd.second - wd.first > m_store.size() ? wd.first + m_store.size() : wd.second,
                  m_store.begin()
               );
         }

      private:
         std::vector<uint8_t> m_store;
   };

   struct QName
   {
      public:
         explicit QName(const std::string& fqdn)
         {
            m_store.reserve(fqdn.size() + 1);

            auto pos = fqdn.size();
            pos = 0;

            while(true)
            {
               auto dotpos = fqdn.find('.', pos);

               auto endpos = (dotpos == fqdn.npos) ? fqdn.size() : dotpos;

               uint8_t sz = (endpos - pos) > 255 ? 255 : (endpos - pos);

               m_store.push_back(sz);

               std::copy(fqdn.data() + pos, fqdn.data() + pos + sz, std::back_inserter(m_store));

               if(dotpos == fqdn.npos)
                  break;

               pos = dotpos + 1;
            }

            m_store.push_back(0);
         }

         auto WireData() const
         {
            return std::make_pair(m_store.cbegin(), m_store.cend());
         }

         void WireData(std::vector<uint8_t>& store)&&
         {
            store = std::move(m_store);
         }

         friend std::ostream& operator<<(std::ostream& os, const QName& rhs)
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
         explicit Question(const std::string& fqdn, uint16_t qtype, uint16_t qclass)
         {
            QName(fqdn).WireData(m_store);

            m_store.resize(m_store.size() + 4);

            QType(qtype);

            QClass(qclass);
         }

         uint16_t QType() const
         {
            return (uint16_t(m_store[m_store.size() - 4 + 0]) << 8) |
                   (uint16_t(m_store[m_store.size() - 4 + 1]) << 0);
         }

         uint16_t QClass() const
         {
            return (uint16_t(m_store[m_store.size() - 4 + 2]) << 8) |
                   (uint16_t(m_store[m_store.size() - 4 + 3]) << 0);
         }

         auto WireData() const
         {
            return std::make_pair(m_store.cbegin(), m_store.cend());
         }

         void WireData(std::vector<uint8_t>& store)&&
         {
            std::move(m_store.cbegin(), m_store.cend(), std::back_inserter(store));
         }

      private:
         void QType(uint16_t v)
         {
            m_store[m_store.size() - 4 + 0] = (v >> 8) & 0xFF;
            m_store[m_store.size() - 4 + 1] = (v >> 0) & 0xFF;
         }

         void QClass(uint16_t v)
         {
            m_store[m_store.size() - 4 + 2] = (v >> 8) & 0xFF;
            m_store[m_store.size() - 4 + 3] = (v >> 0) & 0xFF;
         }

      private:
         std::vector<uint8_t> m_store;
   };
};

#endif
