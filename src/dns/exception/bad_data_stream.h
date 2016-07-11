#pragma once

#include <stdexcept>

namespace dns
{
   namespace exception
   {
      struct bad_data_stream : public std::exception
      {
         public:
            bad_data_stream(const char* const str, int code)
               : m_str(str)
               , m_code(code)
            {
            }

            bad_data_stream(bad_data_stream& rhs)
               : m_str(rhs.m_str)
               , m_code(rhs.m_code)
            {
            }

            bad_data_stream(bad_data_stream&& rhs)
               : m_str(rhs.m_str)
               , m_code(rhs.m_code)
            {
            }

            int code() const noexcept { return m_code; }

            const char* what() const noexcept { return m_str; }

            void operator=(const bad_data_stream&) = delete;
            void operator=(bad_data_stream&&) = delete;

         private:
            const char* const m_str;
            int m_code;
      };
   }
}
