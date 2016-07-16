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
         name_offset_tracker_t(uint16_t offset = 0)
            : m_current_offset(offset)
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

         auto current_offset() const
         {
            return m_current_offset;
         }

         void increment_offset()
         {
            ++m_current_offset;
         }

         template<class Str>
         void save_offset_of(Str&& str)
         {
            m_offset_name_assoc.insert(
               decltype(m_offset_name_assoc)::value_type(
                  m_current_offset,
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
         uint16_t m_current_offset = 0;
         boost::bimap< uint16_t, boost::bimaps::multiset_of<std::string> > m_offset_name_assoc;
   };
}
