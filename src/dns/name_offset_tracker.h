#pragma once

#include <utility>
#include <string>
#include <experimental/optional>
#include <boost/bimap.hpp>

namespace dns
{
   class name_offset_tracker_t
   {
      public:
         name_offset_tracker_t(uint16_t offset = 0)
            : m_current_offset(offset)
         {
         }

         template<class T>
         auto find_offset(T&& k) const
         {
            auto&& i = m_name_offset_assoc.left.find(std::forward<T>(k));

            if(i != m_name_offset_assoc.left.end())
               return std::experimental::optional < decltype(i->second) > {i->second};
            else
               return std::experimental::optional < decltype(i->second) > {};
         }

         template<class T>
         auto find_name(T&& k) const
         {
            auto&& i = m_name_offset_assoc.right.find(std::forward<T>(k));

            if(i != m_name_offset_assoc.right.end())
               return std::experimental::optional < decltype(i->second) > {i->second};
            else
               return std::experimental::optional < decltype(i->second) > {};
         }

         auto current_offset() const
         {
            return m_current_offset;
         }

         void increment_offset(int amount = 1)
         {
            m_current_offset += amount;
         }

         template<class T>
         void save_offset_of(T&& k)
         {
            m_name_offset_assoc.insert(
               decltype(m_name_offset_assoc)::value_type(
                  std::forward<T>(k),
                  m_current_offset
               )
            );
         }

         template<class T, class U>
         void insert(T&& k, U&& u)
         {
            m_name_offset_assoc.insert(
               decltype(m_name_offset_assoc)::value_type(
                  std::forward<U>(u),
                  std::forward<T>(k)
               )
            );
         }

      private:
         uint16_t m_current_offset = 0;
         boost::bimap< std::string, uint16_t > m_name_offset_assoc;
   };
}
