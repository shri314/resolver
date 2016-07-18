#pragma once

namespace util
{
   struct name_builder
   {
      explicit name_builder(char sep = '.')
         : m_sep(sep)
      {
      }

      template<class Str>
      void add_part( Str&& rhs )
      {
         auto&& b = std::cbegin(rhs);
         auto&& e = std::cend(rhs);

         m_name.reserve( m_name.size() + std::distance(b, e) + (m_name.empty() ? 0 : 1) );

         if(!m_name.empty())
            m_name += m_sep;

         m_name += std::forward<Str>(rhs);
      }

      template<class Str>
      void append( Str&& rhs )
      {
         m_name += std::forward<Str>(rhs);
      }

      const std::string& full_name() const&
      {
         return m_name;
      }

      std::string full_name() &&
      {
         return std::move(m_name);
      }

   private:
      std::string m_name;
      const char m_sep;
   };
}
