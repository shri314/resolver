#pragma once

#include <ostream>
#include <string>

#include "dns/op_code.h"
#include "dns/r_code.h"
#include "dns/detail/name_offset_tracker.h"
#include "dns/detail/bin_serialize.h"

namespace dns
{
   class header_t
   {
      public:
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
                        std::string(rhs.QR_Flag() ? "QR" : ""),
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

   inline void save_to(name_offset_tracker_t& tr, const header_t& h)
   {
      save_to(tr, h.ID());

      save_to(tr, static_cast<uint8_t>(
                 (h.QR_Flag() ? 0x80 : 0) |
                 ((static_cast<uint8_t>(h.OpCode()) & 0xF) << 3) |
                 (h.AA_Flag() ? 0x04 : 0) |
                 (h.TC_Flag() ? 0x02 : 0) |
                 (h.RD_Flag() ? 0x01 : 0)));

      save_to(tr, static_cast<uint8_t>(
                 (h.RA_Flag() ? 0x80 : 0) |
                 (h.Res1_Flag() ? 0x40 : 0) |
                 (h.AD_Flag() ? 0x20 : 0) |
                 (h.CD_Flag() ? 0x10 : 0) |
                 (static_cast<uint8_t>(h.RCode()) & 0xF)));

      save_to(tr, h.QdCount());
      save_to(tr, h.AnCount());
      save_to(tr, h.NsCount());
      save_to(tr, h.ArCount());
   }

   template<>
   struct LoadImpl<header_t>
   {
      template<class InputIterator>
      static header_t impl(name_offset_tracker_t& tr, InputIterator& ii, InputIterator end)
      {
         header_t h{};

         {
            h.ID(load_from<uint16_t>(tr, ii, end));
         }

         {
            uint8_t v = load_from<uint8_t>(tr, ii, end);

            h.QR_Flag((v & 0x80) == 0x80 ? true : false);
            h.OpCode(static_cast<op_code_t>((v >> 3) & 0xF));
            h.AA_Flag((v & 0x04) == 0x04 ? true : false);
            h.TC_Flag((v & 0x02) == 0x02 ? true : false);
            h.RD_Flag((v & 0x01) == 0x01 ? true : false);
         }

         {
            uint8_t v = load_from<uint8_t>(tr, ii, end);

            h.RA_Flag((v & 0x80) == 0x80 ? true : false);
            h.Res1_Flag((v & 0x40) == 0x40 ? true : false);
            h.AD_Flag((v & 0x20) == 0x20 ? true : false);
            h.CD_Flag((v & 0x10) == 0x10 ? true : false);
            h.RCode(static_cast<r_code_t>(v & 0xF));
         }

         {
            h.QdCount(load_from<uint16_t>(tr, ii, end));
            h.AnCount(load_from<uint16_t>(tr, ii, end));
            h.NsCount(load_from<uint16_t>(tr, ii, end));
            h.ArCount(load_from<uint16_t>(tr, ii, end));
         }

         return h;
      }
   };
}
