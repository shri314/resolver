#pragma once

#include <ostream>
#include <experimental/optional>
#include <cctype>

namespace util
{
   template<class Iterator>
   inline std::ostream& DumpOct(std::ostream& os, Iterator begin, Iterator end)
   {
      std::experimental::optional<unsigned> z;

      for(; begin != end; ++begin)
      {
         unsigned char x = static_cast<unsigned char>(*begin);

         if(z)
         {
            if(x >= '0' && x <= '9')
            {
               // if current char is a number character, ensure previous number is printed with zero padding

               if(*z < 8)
                  os << "\\00" << std::oct << *z;
               else if(*z < 64)
                  os << "\\0" << std::oct << *z;
            }
            else
               os << "\\" << std::oct << *z;

            z = {};
         }

         switch(x)
         {
            case '\t':
               os << "\\t";
               break;

            case '\f':
               os << "\\f";
               break;

            case '\r':
               os << "\\r";
               break;

            case '\n':
               os << "\\n";
               break;

            case '\v':
               os << "\\v";
               break;

            case '\\':
               os << "\\\\";
               break;

            case '"':
               os << "\\\"";
               break;

            default:
               if(std::isprint(x))
                  os << x;
               else
                  z = static_cast<unsigned>(x);
               break;
         }
      }

      if(z)
         os << "\\" << std::oct << *z;

      return os;
   }

   inline std::string oct_dump(const std::vector<uint8_t>& data)
   {
      std::ostringstream oss;
      DumpOct(oss, data.begin(), data.end());
      return oss.str();
   }

   inline std::string oct_dump(const std::string& data)
   {
      std::ostringstream oss;
      DumpOct(oss, data.begin(), data.end());
      return oss.str();
   }

   inline std::string oct_dump(uint32_t x)
   {
      unsigned char* b = reinterpret_cast<unsigned char*>(&x);

      std::ostringstream oss;
      DumpOct(oss, b, b + sizeof(x));
      return oss.str();
   }

   inline std::string oct_dump(uint16_t x)
   {
      unsigned char* b = reinterpret_cast<unsigned char*>(&x);

      std::ostringstream oss;
      DumpOct(oss, b, b + sizeof(x));
      return oss.str();
   }
}
