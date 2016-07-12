#pragma once

#include <stdexcept>

namespace dns
{
   namespace exception
   {
      struct bad_name : public std::exception
      {
         public:
            bad_name(const char* const str, int code)
               : m_str(str)
               , m_code(code)
            {
            }

            bad_name(bad_name& rhs)
               : m_str(rhs.m_str)
               , m_code(rhs.m_code)
            {
            }

            bad_name(bad_name&& rhs)
               : m_str(rhs.m_str)
               , m_code(rhs.m_code)
            {
            }

            int code() const noexcept { return m_code; }

            const char* what() const noexcept { return m_str; }

            void operator=(const bad_name&) = delete;
            void operator=(bad_name&&) = delete;

         private:
            const char* const m_str;
            int m_code;
      };
   }
}
