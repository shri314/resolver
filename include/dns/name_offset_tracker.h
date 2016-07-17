#pragma once

#include <boost/bimap.hpp>
#include <boost/bimap/multiset_of.hpp>

#include <utility>
#include <string>
#include <experimental/optional>

namespace dns
{
   class name_offset_tracker_t
   {
      public:
         explicit name_offset_tracker_t(uint16_t initial_offset = 0)
            : m_initial_offset(initial_offset)
         {
         }

         template<class Str>
         auto find_offset(Str&& str) const
         {
            auto&& i = m_offset_name_assoc.right.find(std::forward<Str>(str));

            if(i != m_offset_name_assoc.right.end())
               return std::experimental::optional < decltype(i->second) > {i->second};
            else
               return std::experimental::optional < decltype(i->second) > {};
         }

         template<class Off>
         auto find_name(Off&& off) const
         {
            auto&& i = m_offset_name_assoc.left.find(std::forward<Off>(off));

            if(i != m_offset_name_assoc.left.end())
               return std::experimental::optional < decltype(i->second) > {i->second};
            else
               return std::experimental::optional < decltype(i->second) > {};
         }

         uint16_t current_offset() const
         {
            return m_initial_offset + m_store.size();
         }

         const std::vector<uint8_t>& store() const
         {
            return m_store;
         }

         auto store_bi()
         {
            return std::back_inserter(m_store);
         }

         uint8_t save(uint8_t c)
         {
            m_store.push_back(c);
            return c;
         }

         void clear()
         {
            m_store.clear();
            m_offset_name_assoc.clear();
         }

         template<class Str>
         void save_offset_of(Str&& str)
         {
            m_offset_name_assoc.insert(
               decltype(m_offset_name_assoc)::value_type(
                  current_offset(),
                  std::forward<Str>(str)
               )
            );
         }

         template<class Off, class Str>
         void insert(Off&& off, Str&& v)
         {
            m_offset_name_assoc.insert(
               decltype(m_offset_name_assoc)::value_type(
                  std::forward<Off>(off),
                  std::forward<Str>(v)
               )
            );
         }

      private:
         boost::bimap< uint16_t, boost::bimaps::multiset_of<std::string> > m_offset_name_assoc;
         std::vector<uint8_t> m_store;
         uint16_t m_initial_offset = 0;
   };
}
