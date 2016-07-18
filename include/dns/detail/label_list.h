#pragma once

#include <ostream>
#include <string>

namespace dns
{
   class label_list_t
   {
      public:
         label_list_t(std::string name = std::string{})
         {
            Name(std::move(name));
         }

         void Name(std::string name)
         {
            m_name = std::move(name);
         }

         std::string Name() const
         {
            return m_name;
         }

         friend std::ostream& operator<<(std::ostream& os, const label_list_t& rhs)
         {
            return os << "[" << rhs.Name() << "]";
         }

      private:
         std::string m_name;
   };
}
