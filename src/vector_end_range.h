#pragma once

#include <vector>

namespace DnsProtocol
{
   namespace detail
   {
      class vector_end_range // fixme = templatize this
      {
         public:
            using iterator = std::vector<uint8_t>::iterator;
            using const_iterator = std::vector<uint8_t>::const_iterator;

            std::vector<uint8_t>& m_ref;
            std::vector<uint8_t>::size_type m_ref_base_size;

            explicit vector_end_range(std::vector<uint8_t>& ref, size_t resize = 0)
               : m_ref(ref)
               , m_ref_base_size(ref.size())
            {
               if(resize > 0)
                  m_ref.resize( m_ref_base_size + resize );
            }

            vector_end_range(const vector_end_range&) = delete;

            vector_end_range(vector_end_range&& rhs)
               : m_ref(rhs.m_ref)
               , m_ref_base_size(rhs.m_ref_base_size)
            {
               rhs.m_ref_base_size = rhs.m_ref.size();
            }

            void operator=(const vector_end_range& rhs) = delete;
            void operator=(vector_end_range&& rhs) = delete;

            auto size() const
            {
               return m_ref.size() - m_ref_base_size;
            }

            auto push_back(uint8_t x)
            {
               return m_ref.push_back(x);
            }

            auto begin()
            {
               return m_ref.begin() + m_ref_base_size;
            }

            auto begin() const
            {
               return m_ref.begin() + m_ref_base_size;
            }

            auto cbegin() const
            {
               return m_ref.cbegin() + m_ref_base_size;
            }

            auto end()
            {
               return m_ref.end();
            }

            auto end() const
            {
               return m_ref.end();
            }

            uint8_t& operator[](size_t i)
            {
               return m_ref[i + m_ref_base_size];
            }

            const uint8_t& operator[](size_t i) const
            {
               return m_ref[i + m_ref_base_size];
            }

            ~vector_end_range()
            {
               if(size())
                  m_ref.erase(begin(), end());
            }
      };
   }
}
