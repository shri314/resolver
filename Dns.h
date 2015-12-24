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
         private:
            uint16_t m_ID;
            uint16_t m_Flags;
            uint16_t m_QdCount;
            uint16_t m_AnCount;
            uint16_t m_NsCount;
            uint16_t m_ArCount;

         public:
            void ID(uint16_t ID_)
            {
               m_ID = ID_;
            }

            uint16_t ID() const
            {
               return m_ID;
            }

            void QR_Flag(bool b)
            {
               m_Flags |= (b ? 0x8000 : 0x0000);
            }

            bool QR_Flag() const
            {
               return m_Flags & 0x8000 == 0x8000;
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

      } m_Header;

      struct ALIGNAS QuestionPod
      {
      };

      struct QName
      {
      public:
         explicit QName(const std::string& fqdn)
         {
            m_fqdn.reserve( fqdn.size() + 1 );

            auto pos = fqdn.size(); pos = 0;

            while(true)
            {
               auto dotpos = fqdn.find('.', pos);

               auto endpos = (dotpos == fqdn.npos) ? fqdn.size() : dotpos;

               uint8_t sz = (endpos - pos) > 255 ? 255 : (endpos - pos);

               m_fqdn.push_back(sz);

               std::copy( fqdn.data() + pos, fqdn.data() + pos + sz, std::back_inserter(m_fqdn) );

               if(dotpos == fqdn.npos)
                  break;

               pos = dotpos + 1;
            }

            m_fqdn.push_back(0);
         }

         std::vector<uint8_t> Data() const
         {
            return m_fqdn;
         }

         void FillData(std::ostream& os) const
         {
            for(auto c : this->Data())
               os << c;
         }

         friend std::ostream& operator<<( std::ostream& os, const QName& rhs )
         {
            unsigned c = 0;
            for( auto x : rhs.m_fqdn )
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
