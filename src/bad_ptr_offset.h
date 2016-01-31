#pragma once

#include <stdexcept>

namespace DnsProtocol
{
   struct bad_ptr_offset : public std::exception
   {
      public:
         bad_ptr_offset(const char* const str, int code)
            : m_str(str)
            , m_code(code)
         {
         }

         bad_ptr_offset(bad_ptr_offset& rhs)
            : m_str(rhs.m_str)
            , m_code(rhs.m_code)
         {
         }

         bad_ptr_offset(bad_ptr_offset&& rhs)
            : m_str(rhs.m_str)
            , m_code(rhs.m_code)
         {
         }

         int code() const noexcept { return m_code; }

         const char* what() const noexcept { return m_str; }

         void operator=(const bad_ptr_offset&) = delete;
         void operator=(bad_ptr_offset&&) = delete;

      private:
         const char* const m_str;
         int m_code;
   };
}
