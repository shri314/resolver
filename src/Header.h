#pragma once

#include "vector_end_range.h"
#include "bad_data_stream.h"
#include <iostream>

namespace DnsProtocol
{
   struct Header_t
   {
      public:
         explicit Header_t(std::vector<uint8_t>& store)
            : m_store(store, 12)
         {
            ZCode(0);
         }

         explicit Header_t(std::vector<uint8_t>& store, const Header_t& rhs)
            : m_store(store, 12)
         {
            std::copy( rhs.m_store.begin(), rhs.m_store.end(), m_store.begin() );
         }

         Header_t& ID(uint16_t v)
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

         Header_t& QR_Flag(bool v)
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

         Header_t& OpCode(uint16_t v)
         {
            m_store[2] |= (v & 0xF) << 3;
            m_store[2] &= ~((~v & 0xF) << 3);

            return *this;
         }

         uint16_t OpCode() const
         {
            return (m_store[2] >> 3) & 0xF;
         }

         Header_t& AA_Flag(bool v)
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

         Header_t& TC_Flag(bool v)
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

         Header_t& RD_Flag(bool v)
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

         Header_t& RA_Flag(bool v)
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

         Header_t& ZCode(uint16_t v)
         {
            m_store[3] |= (v & 0x7) << 4;
            m_store[3] &= ~((~v & 0x7) << 4);

            return *this;
         }

         uint16_t ZCode()
         {
            return (m_store[3] >> 4) & 0x7;
         }

         Header_t& RCode(uint16_t v)
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

         Header_t& QdCount(uint16_t v)
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

         Header_t& AnCount(uint16_t v)
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

         Header_t& NsCount(uint16_t v)
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

         Header_t& ArCount(uint16_t v)
         {
            m_store[10] = (v >> 8) & 0xFF;
            m_store[11] = (v >> 0) & 0xFF;

            return *this;
         }

         uint16_t Size() const
         {
            return m_store.size();
         }

         uint16_t ArCount() const
         {
            return (uint16_t(m_store[10]) << 8)
                   | (uint16_t(m_store[11]) << 0);
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

         template<class Iter>
         void Load(Iter& begin, Iter end)
         {
            if(std::distance(begin, end) < m_store.size())
               throw bad_data_stream("truncated", 1);

            std::copy(begin, begin + m_store.size(), m_store.begin());

            begin += m_store.size();
         }

         friend std::ostream& operator<<(std::ostream& os, const Header_t& rhs)
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
                        std::string(rhs.RA_Flag() ? "RA" : "")
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
         detail::vector_end_range m_store;
   };
}
