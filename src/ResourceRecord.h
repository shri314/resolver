#pragma once

#include "vector_end_range.h"

#include "bad_data_stream.h"

#include <boost/asio/buffer.hpp>

#include <vector>
#include <string>
#include <ostream>
#include <algorithm> // std::copy

namespace DnsProtocol
{
   struct ResourceRecord_t
   {
      public:
         explicit ResourceRecord_t(std::vector<uint8_t>& store)
            : m_rrname(store)
            , m_store(store, 10)
            , m_rdata(store)
         {
         }

         ResourceRecord_t& RRName(const std::string& v)
         {
            m_rrname.Set(v);
            m_store.slide_to_end(10);
            m_rdata.slide_to_end();

            return *this;
         }

         auto RRName() const
         {
            return m_rrname.Get();
         }

         ResourceRecord_t& Type(uint16_t v)
         {
            m_store[0] = (v >> 8) & 0xFF;
            m_store[1] = (v >> 0) & 0xFF;

            return *this;
         }

         uint16_t Type() const
         {
            return (uint16_t(m_store[0]) << 8)
                   | (uint16_t(m_store[1]) << 0);
         }

         ResourceRecord_t& Class(uint16_t v)
         {
            m_store[2] = (v >> 8) & 0xFF;
            m_store[3] = (v >> 0) & 0xFF;

            return *this;
         }

         uint16_t Class() const
         {
            return (uint16_t(m_store[2]) << 8)
                   | (uint16_t(m_store[3]) << 0);
         }

         ResourceRecord_t& TTL(uint32_t v)
         {
            m_store[4] = (v >> 24) & 0xFF;
            m_store[5] = (v >> 16) & 0xFF;
            m_store[6] = (v >> 8) & 0xFF;
            m_store[7] = (v >> 0) & 0xFF;

            return *this;
         }

         uint32_t TTL() const
         {
            return (uint32_t(m_store[4]) << 24)
                   | (uint32_t(m_store[5]) << 16)
                   | (uint32_t(m_store[6]) << 8)
                   | (uint32_t(m_store[7]) << 0);
         }

         uint16_t RDLength() const
         {
            return (uint16_t(m_store[8]) << 8)
                   | (uint16_t(m_store[9]) << 0);
         }

         ResourceRecord_t& RData(std::vector<uint8_t> data)
         {
            if(data.size() > 0xFFFF)
               throw bad_data_stream("length too long", 3);

            RDLength(data.size());

            m_rdata.assign(data.begin(), data.end());

            return *this;
         }

         auto RData() const
         {
            return std::make_pair( m_rdata.begin(), m_rdata.end() );
         }

         void Save(std::vector<boost::asio::const_buffer>& buf) const
         {
            m_rrname.Save(buf);
            buf.push_back(boost::asio::const_buffer{&m_store[0], m_store.size()});
            buf.push_back(boost::asio::const_buffer{&m_rdata[0], m_rdata.size()});
         }

         void Save(std::vector<uint8_t>& buf) const
         {
            m_rrname.Save(buf);
            std::copy(m_store.begin(), m_store.end(), std::back_inserter(buf));
            std::copy(m_rdata.begin(), m_rdata.end(), std::back_inserter(buf));
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
            m_rrname.Load(begin, end);
            m_store.slide_to_end(10);

            if(std::distance(begin, end) < m_store.size())
               throw bad_data_stream("truncated", 4);

            std::copy(begin, begin + m_store.size(), m_store.begin());

            begin += m_store.size();

            m_rdata.slide_to_end(RDLength());

            if(std::distance(begin, end) < m_rdata.size())
               throw bad_data_stream("truncated", 5);

            std::copy(begin, begin + RDLength(), m_rdata.begin());

            begin += m_rdata.size();
         }

         friend std::ostream& operator<<(std::ostream& os, const ResourceRecord_t& rhs)
         {
            return os << "{ RRName=" << rhs.m_rrname << ", Type=" << rhs.Type() << ", Class=" << rhs.Class() << ", TTL=" << rhs.TTL() << ", RDLength=" << rhs.RDLength() << " }";
         }

         uint16_t Size() const
         {
            return m_rrname.Size() + m_store.size() + m_rdata.size();
         }

      private:
         ResourceRecord_t& RDLength(uint16_t v)
         {
            m_store[8] = (v >> 8) & 0xFF;
            m_store[9] = (v >> 0) & 0xFF;

            return *this;
         }

      private:
         LabelList_t m_rrname;
         detail::vector_end_range m_store;
         detail::vector_end_range m_rdata;
   };
}
