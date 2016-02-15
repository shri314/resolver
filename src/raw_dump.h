#pragma once

std::string OctRep(unsigned char x, bool keep_printables = false)
{
   std::ostringstream oss;

   if(isalpha(x) || (keep_printables && std::isprint(x) && !std::isspace(x)))
      oss << x;
   else
   {
      if(x < 8)
         oss << "\\00" << std::oct << (unsigned)x;
      else if(x < 64)
         oss << "\\0" << std::oct << (unsigned)x;
      else
         oss << "\\" << std::oct << (unsigned)x;
   }

   return oss.str();
}

std::string OctRep(const std::vector<uint8_t>& data)
{
   std::ostringstream oss;
   for(auto x : data)
      oss << OctRep((unsigned char)x);

   return oss.str();
}

std::string OctRep(const std::string& data)
{
   std::ostringstream oss;
   for(auto x : data)
      oss << OctRep((unsigned char)x);

   return oss.str();
}

std::string OctRep(uint32_t x)
{
   unsigned char* b = reinterpret_cast<unsigned char*>(&x);
   return OctRep(std::string(b, b + sizeof(x)));
}

std::string OctRep(uint16_t x)
{
   unsigned char* b = reinterpret_cast<unsigned char*>(&x);
   return OctRep(std::string(b, b + sizeof(x)));
}


