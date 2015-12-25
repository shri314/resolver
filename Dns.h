#ifndef Dns_h__
#define Dns_h__

#include <string>
#include <vector>
#include <ostream>
#include <algorithm> // std::copy

#define ALIGNAS alignas(1)

namespace DnsProtocol
{
   struct ALIGNAS HeaderPod
   {
      public:
         void ID(uint16_t ID_)
         {
            m_store[0] = (ID_ & 0x00FF) >> 0;
            m_store[1] = (ID_ & 0xFF00) >> 8;
         }

         uint16_t ID() const
         {
            return  (uint16_t(m_store[1]) << 8)
                  | (uint16_t(m_store[0]) << 0);
         }

         void QR_Flag(bool b)
         {
            m_store[2] |= (b ? 0x8000 : 0x0000);
         }

         bool QR_Flag() const
         {
            return m_store[2] & 0x8000 == 0x8000;
         }

         void OpCode(uint8_t OpCode_)
         {
            m_Flags |= (OpCode_ & 0xF) << 11;
         }

         uint8_t OpCode() const
         {
            return (m_Flags & 0x7800) >> 11;
         }

         void AA_Flag(bool b)
         {
            m_Flags |= (b ? 0x0400 : 0x0000);
         }

         bool AA_Flag() const
         {
            return m_Flags & 0x0400 == 0x0400;
         }

         void TC_Flag(bool b)
         {
            m_Flags |= (b ? 0x0200 : 0x0000);
         }

         bool TC_Flag() const
         {
            return m_Flags & 0x0200 == 0x0200;
         }

         void RD_Flag(bool b)
         {
            m_Flags |= (b ? 0x0100 : 0x0000);
         }

         bool RD_Flag() const
         {
            return m_Flags & 0x0100 == 0x0100;
         }

         //////////////

         void RA_Flag(bool b)
         {
            m_Flags |= (b ? 0x0080 : 0x0000);
         }

         bool RA_Flag() const
         {
            return m_Flags & 0x0080 == 0x0080;
         }

         void Z_Flag()
         {
            m_Flags &= ~0x0070;
         }

         void RCode(uint8_t RCode_)
         {
            m_Flags |= (RCode_ & 0xF);
         }

         uint8_t RCode() const
         {
            return (m_Flags & 0xF);
         }

         void QdCount(uint16_t QdCount_)
         {
            m_QdCount = QdCount_;
         }

         uint16_t QdCount() const
         {
            return m_QdCount;
         }

         void AnCount(uint16_t AnCount_)
         {
            m_AnCount = AnCount_;
         }

         uint16_t AnCount() const
         {
            return m_AnCount;
         }

         void NsCount(uint16_t NsCount_)
         {
            m_NsCount = NsCount_;
         }

         uint16_t NsCount() const
         {
            return m_NsCount;
         }

         void ArCount(uint16_t ArCount_)
         {
            m_ArCount = ArCount_;
         }

         uint16_t ArCount() const
         {
            return m_ArCount;
         }

         auto WireData() const
         {
            return std::make_pair(m_store.cbegin(), m_store.cend());
         }

         std::vector<uint8_t> m_store;

         HeaderPod()
         {
            m_store.resize(12);
         }

      private:

         uint16_t m_ID = 0;
         uint16_t m_Flags = 0;
         uint16_t m_QdCount = 0;
         uint16_t m_AnCount = 0;
         uint16_t m_NsCount = 0;
         uint16_t m_ArCount = 0;
   };

   struct QName
   {
      public:
         explicit QName(const std::string& fqdn)
         {
            m_fqdn.reserve(fqdn.size() + 1);

            auto pos = fqdn.size();
            pos = 0;

            while(true)
            {
               auto dotpos = fqdn.find('.', pos);

               auto endpos = (dotpos == fqdn.npos) ? fqdn.size() : dotpos;

               uint8_t sz = (endpos - pos) > 255 ? 255 : (endpos - pos);

               m_fqdn.push_back(sz);

               std::copy(fqdn.data() + pos, fqdn.data() + pos + sz, std::back_inserter(m_fqdn));

               if(dotpos == fqdn.npos)
                  break;

               pos = dotpos + 1;
            }

            m_fqdn.push_back(0);
         }

         auto WireData() const
         {
            return std::make_pair(m_fqdn.cbegin(), m_fqdn.cend());
         }

         friend std::ostream& operator<<(std::ostream& os, const QName& rhs)
         {
            unsigned c = 0;
            for(auto x : rhs.m_fqdn)
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
         std::vector<uint8_t> m_fqdn;
   };
};

#endif
