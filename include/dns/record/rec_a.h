#pragma once

#include <boost/lexical_cast.hpp>

#include <string>
#include <ostream>

namespace dns
{
   class rec_a_t
   {
      public:
         explicit rec_a_t(const std::string& address)
         {
            DotAddress(address);
         }

         explicit rec_a_t(uint32_t address)
            : m_address(address)
         {
         }

         explicit rec_a_t()
            : rec_a_t{0}
         {
         }

         void Address(uint32_t v)
         {
            m_address = v;
         }

         uint32_t Address() const
         {
            return m_address;
         }

         std::string DotAddress() const
         {
            std::string result;
            result.reserve(16);

            result += boost::lexical_cast<std::string>( ( m_address >> 24 ) & 0xFF );
            result += '.';                                                  
            result += boost::lexical_cast<std::string>( ( m_address >> 16 ) & 0xFF );
            result += '.';                                                  
            result += boost::lexical_cast<std::string>( ( m_address >> 8  ) & 0xFF );
            result += '.';                                                  
            result += boost::lexical_cast<std::string>( ( m_address >> 0  ) & 0xFF );

            return result;
         }

         void DotAddress(const std::string& v)
         {
            uint32_t result = 0;
            std::string::size_type pos = 0;
            for(int p = 3; p >= 0; p--)
            {
               auto dot_pos = v.find('.', pos);
               result |= ( boost::lexical_cast<uint32_t>(v.substr(pos, dot_pos - pos)) << (p*8) );
               if(dot_pos == v.npos)
                  break;
               pos = dot_pos + 1;
            }

            m_address = result;
         }

         friend std::ostream& operator<<(std::ostream& os, const rec_a_t& rhs)
         {
            return os << "[" << rhs.DotAddress() << "]";
         }

         friend bool operator==(const rec_a_t& lhs, const rec_a_t& rhs)
         {
            return lhs.Address() == rhs.Address();
         }

         static const rr_type_t m_type = dns::rr_type_t::rec_a;

      private:
         uint32_t m_address;
   };

   inline void save_to(name_offset_tracker_t& tr, const rec_a_t& r)
   {
      save_to(tr, r.Address());
   }

   template<>
   struct LoadImpl<rec_a_t>
   {
      template<class InputIterator>
      static rec_a_t impl(name_offset_tracker_t& tr, InputIterator& ii, InputIterator end)
      {
         rec_a_t r{};

         r.Address(load_from<uint32_t>(tr, ii, end));

         return r;
      }
   };
}
