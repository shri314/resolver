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
            std::vector<uint8_t>::size_type m_first;
            std::vector<uint8_t>::size_type m_size;

            explicit vector_end_range(std::vector<uint8_t>& ref, std::vector<uint8_t>::size_type initsz = 0)
               : m_ref(ref)
               , m_size(ref.size())
            {
               this->slide_to_end(initsz);
            }

            vector_end_range(vector_end_range&& rhs)
               : m_ref(rhs.m_ref)
               , m_first(rhs.m_first)
               , m_size(rhs.m_size)
            {
               rhs.m_size = 0;
            }

            vector_end_range(const vector_end_range&) = delete;
            void operator=(const vector_end_range& rhs) = delete;
            void operator=(vector_end_range&& rhs) = delete;

            auto size() const
            {
               return m_ref.size() - m_first;
            }

            void push_back(uint8_t x)
            {
               m_ref.push_back(x);
               ++m_size;
            }

            auto begin()
            {
               return m_ref.begin() + m_first;
            }

            auto begin() const
            {
               return m_ref.begin() + m_first;
            }

            auto cbegin() const
            {
               return m_ref.cbegin() + m_first;
            }

            auto end()
            {
               return this->begin() + m_size;
            }

            auto end() const
            {
               return this->begin() + m_size;
            }

            auto cend() const
            {
               return this->cbegin() + m_size;
            }

            uint8_t& operator[](std::size_t i)
            {
               return m_ref[i + m_first];
            }

            const uint8_t& operator[](std::size_t i) const
            {
               return m_ref[i + m_first];
            }

            auto empty() const
            {
               return m_size == 0;
            }

            auto clear()
            {
               if(m_size > 0)
               {
                  m_ref.erase(this->begin(), this->end());
                  m_size = 0;
               }
            }

            auto resize(std::size_t newsz)
            {
               m_ref.resize(m_first + newsz);
               m_size = newsz;
            }

            template <class InputIterator>
            void assign(InputIterator first, InputIterator last)
            {
               this->resize(std::distance(first, last));

               std::copy(first, last, this->begin());
            }

            void slide_to_end(std::size_t initsz = 0)
            {
               m_first = m_ref.size();
               m_size = 0;

               if(initsz > 0)
                  this->resize(initsz);
            }

            ~vector_end_range()
            {
               this->clear();
            }
      };
   }
}
