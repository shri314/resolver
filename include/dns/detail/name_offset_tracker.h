#pragma once

#include <experimental/optional>
#include <utility>
#include <string>
#include <vector>
#include <memory>
#include <algorithm>
#include <map>

namespace dns
{
   class name_offset_tracker_t
   {
      public:
         explicit name_offset_tracker_t(uint16_t initial_offset = 0)
            : m_initial_offset{initial_offset}
            , m_end_offset(m_initial_offset)
            , m_current_offset(m_initial_offset)
            , m_store{ std::make_shared<std::vector<uint8_t>>(m_initial_offset) }
            , m_name_offset_assoc{ std::make_shared<std::multimap<std::string, uint16_t>>() }
         {
         }

         template<class Str>
         explicit name_offset_tracker_t(Str&& str)
            : m_initial_offset(static_cast<uint16_t>(std::distance(std::cbegin(str), std::cend(str))))
            , m_end_offset(m_initial_offset)
            , m_current_offset(m_initial_offset)
            , m_store{ std::make_shared<std::vector<uint8_t>>(std::cbegin(str), std::cbegin(str) + m_initial_offset) }
            , m_name_offset_assoc{ std::make_shared<std::multimap<std::string, uint16_t>>() }
         {
         }

         name_offset_tracker_t(name_offset_tracker_t&&) = default;
         name_offset_tracker_t& operator=(name_offset_tracker_t&&) = default;
         name_offset_tracker_t& operator=(const name_offset_tracker_t&) = delete;

         template<class Str>
         auto find_offset(Str&& str) const
         {
            auto&& i = m_name_offset_assoc->find(std::forward<Str>(str));

            if(i != m_name_offset_assoc->end())
               return std::experimental::optional < decltype(i->second) > {i->second};
            else
               return std::experimental::optional < decltype(i->second) > {};
         }

         auto slice(uint16_t ptr_offset, uint16_t end_offset) const
         {
            if(ptr_offset < current_offset() && end_offset <= current_offset() && ptr_offset <= end_offset)
            {
               return std::experimental::optional<name_offset_tracker_t>
               {
                  name_offset_tracker_t{
                     *this,
                     ptr_offset,
                     end_offset,
                  }
               };
            }

            return std::experimental::optional<name_offset_tracker_t> {};
         }

         uint16_t current_offset() const
         {
            return m_current_offset;
         }

         auto cbegin() const
         {
            return m_store->cbegin() + m_initial_offset;
         }

         auto cend() const
         {
            return m_store->cbegin() + m_end_offset;
         }

         std::vector<uint8_t> store() const
         {
            return std::vector<uint8_t>(cbegin(), cend());
         }

         uint8_t save(uint8_t c)
         {
            if(m_current_offset >= m_store->size())
            {
               m_store->resize( m_store->size() + 1 );
               ++m_end_offset;
            }

            m_store->at(m_current_offset) = c;

            m_current_offset++;

            return c;
         }

         template<class Str>
         void save_offset_of(Str&& str)
         {
            m_name_offset_assoc->emplace(std::forward<Str>(str), current_offset());
         }

      private:
         name_offset_tracker_t(const name_offset_tracker_t& rhs, uint16_t b_offset, uint16_t e_offset)
            : m_initial_offset(b_offset)
            , m_end_offset(e_offset)
            , m_current_offset(m_initial_offset)
            , m_store(rhs.m_store)
            , m_name_offset_assoc(rhs.m_name_offset_assoc)
         {
         }

      private:
         uint16_t m_initial_offset = 0;
         uint16_t m_end_offset = 0;
         uint16_t m_current_offset = 0;
         std::shared_ptr< std::vector<uint8_t> > m_store;
         std::shared_ptr< std::multimap<std::string, uint16_t> > m_name_offset_assoc;
   };
}
