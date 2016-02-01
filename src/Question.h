#pragma once

#include "vector_end_range.h"

#include "bad_name.h"
#include "bad_data_stream.h"

#include <boost/asio/buffer.hpp>

#include <vector>
#include <string>
#include <ostream>
#include <algorithm> // std::copy

namespace DnsProtocol
{
   struct Question_t
   {
      public:
         explicit Question_t(std::vector<uint8_t>& store)
            : m_qname(store)
            , m_store(store, 4)
         {
         }

         Question_t& QName(const std::string& qname)
         {
            m_qname.Set(qname);
            m_store.slide_to_end(4);

            return *this;
         }

         auto QName() const
         {
            return m_qname.Get();
         }

         Question_t& QType(uint16_t v)
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

         Question_t& QClass(uint16_t v)
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

         void Save(std::vector<boost::asio::const_buffer>& buf) const
         {
            m_qname.Save(buf);
            buf.push_back(boost::asio::const_buffer{&m_store[0], m_store.size()});
         }

         void Save(std::vector<uint8_t>& buf) const
         {
            m_qname.Save(buf);
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
            m_qname.Load(begin, end);
            m_store.slide_to_end(4);

            if(std::distance(begin, end) < m_store.size())
               throw bad_data_stream("truncated", 3);

            std::copy(begin, begin + m_store.size(), m_store.begin());

            begin += m_store.size();
         }

         friend std::ostream& operator<<(std::ostream& os, const Question_t& rhs)
         {
            return os << "{ QName=" << rhs.m_qname << ", QType=" << rhs.QType() << ", QClass=" << rhs.QClass() << " }";
         }

         uint16_t Size() const
         {
            return m_qname.Size() + m_store.size();
         }

      private:
         LabelList_t m_qname;
         detail::vector_end_range m_store;
   };
}
