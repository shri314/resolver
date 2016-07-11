#pragma once

#include <ostream>
#include <string>

#include "dns/op_code.h"
#include "dns/r_code.h"

#include "dns/exception/bad_data_stream.h"

namespace dns
{
   class header_t
   {
      public:
      public:
         template<class OutputIterator>
         OutputIterator save_to(OutputIterator o)
         {
            {
               *o++ = static_cast<uint8_t>(m_ID >> 8) & 0xFF;
               *o++ = static_cast<uint8_t>(m_ID >> 0) & 0xFF;
            }

            {
               *o++ = (m_QR ? 0x80 : 0) |
                      ((static_cast<uint8_t>(m_OpCode) & 0xF) << 3) |
                      (m_AA ? 0x04 : 0) |
                      (m_TC ? 0x02 : 0) |
                      (m_RD ? 0x01 : 0);
            }

            {
               *o++ = (m_RA ? 0x80 : 0) |
                      (m_Res1 ? 0x40 : 0) |
                      (m_AD ? 0x20 : 0) |
                      (m_CD ? 0x10 : 0) |
                      (static_cast<uint8_t>(m_RCode) & 0xF);
            }

            {
               *o++ = static_cast<uint8_t>(m_QdCount >> 8) & 0xFF;
               *o++ = static_cast<uint8_t>(m_QdCount >> 0) & 0xFF;
            }

            {
               *o++ = static_cast<uint8_t>(m_AnCount >> 8) & 0xFF;
               *o++ = static_cast<uint8_t>(m_AnCount >> 0) & 0xFF;
            }

            {
               *o++ = static_cast<uint8_t>(m_NsCount >> 8) & 0xFF;
               *o++ = static_cast<uint8_t>(m_NsCount >> 0) & 0xFF;
            }

            {
               *o++ = static_cast<uint8_t>(m_ArCount >> 8) & 0xFF;
               *o++ = static_cast<uint8_t>(m_ArCount >> 0) & 0xFF;
            }

            return o;
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

            {
               m_ID = static_cast<uint16_t>(next()) << 8;
               m_ID |= static_cast<uint16_t>(next());
            }

            {
               uint8_t v = static_cast<uint8_t>(next());

               m_QR = (v & 0x80) == 0x80 ? true : false;
               m_OpCode = static_cast<op_code_t>((v >> 3) & 0xF);
               m_AA = (v & 0x04) == 0x04 ? true : false;
               m_TC = (v & 0x02) == 0x02 ? true : false;
               m_RD = (v & 0x01) == 0x01 ? true : false;
            }

            {
               uint8_t v = static_cast<uint8_t>(next());

               m_RA = (v & 0x80) == 0x80 ? true : false;
               m_Res1 = (v & 0x40) == 0x40 ? true : false;
               m_AD = (v & 0x20) == 0x20 ? true : false;
               m_CD = (v & 0x10) == 0x10 ? true : false;
               m_RCode = static_cast<r_code_t>(v & 0xF);
            }

            {
               m_QdCount = static_cast<uint16_t>(next()) << 8;
               m_QdCount |= static_cast<uint16_t>(next());
            }

            {
               m_AnCount = static_cast<uint16_t>(next()) << 8;
               m_AnCount |= static_cast<uint16_t>(next());
            }

            {
               m_NsCount = static_cast<uint16_t>(next()) << 8;
               m_NsCount |= static_cast<uint16_t>(next());
            }

            {
               m_ArCount = static_cast<uint16_t>(next()) << 8;
               m_ArCount |= static_cast<uint16_t>(next());
            }

            return cur_pos;
         }

         uint16_t ID() const
         {
            return m_ID;
         }

         void ID(uint16_t v)
         {
            m_ID = v;
         }

         bool QR_Flag() const
         {
            return m_QR;
         }

         void QR_Flag(bool v)
         {
            m_QR = v;
         }

         op_code_t OpCode() const
         {
            return m_OpCode;
         }

         void OpCode(op_code_t v)
         {
            m_OpCode = v;
         }

         bool AA_Flag() const
         {
            return m_AA;
         }

         void AA_Flag(bool v)
         {
            m_AA = v;
         }

         bool TC_Flag() const
         {
            return m_TC;
         }

         void TC_Flag(bool v)
         {
            m_TC = v;
         }

         bool RD_Flag() const
         {
            return m_RD;
         }

         void RD_Flag(bool v)
         {
            m_RD = v;
         }

         bool RA_Flag() const
         {
            return m_RA;
         }

         void RA_Flag(bool v)
         {
            m_RA = v;
         }

         bool Res1_Flag() const
         {
            return m_Res1;
         }

         void Res1_Flag(bool v)
         {
            m_Res1 = v;
         }

         bool AD_Flag() const
         {
            return m_AD;
         }

         void AD_Flag(bool v)
         {
            m_AD = v;
         }

         bool CD_Flag() const
         {
            return m_CD;
         }

         void CD_Flag(bool v)
         {
            m_CD = v;
         }

         r_code_t RCode() const
         {
            return m_RCode;
         }

         void RCode(r_code_t v)
         {
            m_RCode = v;
         }

         uint16_t QdCount() const
         {
            return m_QdCount;
         }

         void QdCount(uint16_t v)
         {
            m_QdCount = v;
         }

         uint16_t AnCount() const
         {
            return m_AnCount;
         }

         void AnCount(uint16_t v)
         {
            m_AnCount = v;
         }

         uint16_t NsCount() const
         {
            return m_NsCount;
         }

         void NsCount(uint16_t v)
         {
            m_NsCount = v;
         }

         uint16_t ArCount() const
         {
            return m_ArCount;
         }

         void ArCount(uint16_t v)
         {
            m_ArCount = v;
         }

         friend std::ostream& operator<<(std::ostream& os, const header_t& rhs)
         {
            os << "{ ";
            os << "ID=" << rhs.ID() << ", ";
            {
               os << "Flags=[";
               std::string sep = "";
               for(auto F :
                     {
                        std::string(rhs.QR_Flag() ? "RES" : "QRY"),
                        std::string(rhs.AA_Flag() ? "AA" : ""),
                        std::string(rhs.TC_Flag() ? "TC" : ""),
                        std::string(rhs.RD_Flag() ? "RD" : ""),
                        std::string(rhs.RA_Flag() ? "RA" : ""),
                        std::string(rhs.AD_Flag() ? "AD" : ""),
                        std::string(rhs.CD_Flag() ? "CD" : "")
                     })
               {
                  if(!F.empty())
                  {
                     os << sep << F;
                     if(sep.empty())
                        sep = ",";
                  }
               }
               os << "], ";
            }
            os << "OpCode=" << rhs.OpCode() << ", ";
            os << "RCode=" << rhs.RCode() << ", ";

            os << "QdCount=" << rhs.QdCount() << ", ";
            os << "AnCount=" << rhs.AnCount() << ", ";
            os << "NsCount=" << rhs.NsCount() << ", ";
            os << "ArCount=" << rhs.ArCount() << " ";
            os << "}";

            return os;
         }

      private:
         uint16_t m_ID = 0;

         bool m_QR = false;
         op_code_t m_OpCode = op_code_t::query;
         bool m_AA = false;
         bool m_TC = false;
         bool m_RD = false;

         bool m_RA = false;
         bool m_Res1 = false;
         bool m_AD = false;
         bool m_CD = false;
         r_code_t m_RCode = r_code_t::no_error;

         uint16_t m_QdCount = 0;
         uint16_t m_AnCount = 0;
         uint16_t m_NsCount = 0;
         uint16_t m_ArCount = 0;
   };
}
