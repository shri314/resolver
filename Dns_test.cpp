#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE Dns_test
#include <boost/test/unit_test.hpp>

#include "Dns.h"

#include <string>
#include <sstream>
#include <iostream>

std::string OctRep(unsigned char x, bool keep_printables = false)
{
   std::ostringstream oss;

   if( keep_printables && std::isprint(x) && !std::isspace(x) )
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

std::string OctRep(std::string data)
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

using namespace std::string_literals;

BOOST_AUTO_TEST_CASE(qname_serialization)
{
   {
      DnsProtocol::QName qn{"www.yahoo.com"};

      std::ostringstream oss;
      oss << qn;

      BOOST_TEST(oss.str() == "[3]www[5]yahoo[3]com[0]");
   }

   {
      DnsProtocol::QName qn{"www.yahoo.com"};

      auto&& wd = qn.WireData();

      BOOST_TEST(std::string(wd.first, wd.second) == "\003www\005yahoo\003com\000"s);
   }

   {
      DnsProtocol::HeaderPod h;

      h.ID(100);

   }

   {
      DnsProtocol::HeaderPod h;

      auto&& wd = h.WireData();

      std::string exp;
      exp.resize(2 * 6);

      BOOST_CHECK_EQUAL(std::string(wd.first, wd.second), exp);
   }

   {
      DnsProtocol::HeaderPod h;
      h.ID(18365);
      // h.QR_Flag(1);

      auto&& wd = h.WireData();

      std::cout << OctRep((uint16_t)18365) << "\n";

      BOOST_CHECK_EQUAL(h.ID(), 18365);
      // BOOST_CHECK_EQUAL(h.QR_Flag(), true);

      std::cout << OctRep(std::string(wd.first, wd.second)) << std::endl;

      BOOST_CHECK_EQUAL( OctRep(std::string(wd.first, wd.second)), OctRep("\275\107\000\000\000\000\000\000\000\000\000\000"s));
   }

   {
      std::cout << "======\n";
      std::string x = "\275\107\001\040\000\001\000\000\000\000\000\001"s;
      std::cout << OctRep(x) << "\n";

      DnsProtocol::HeaderPod h;
      auto&& wd = h.WireData();
      std::copy( x.data(), x.data() + x.size(), h.m_store.begin() );

      std::cout << "ID=" << (int)h.ID() << "\n";
      std::cout << "QR_Flag=" << (int)h.QR_Flag() << "\n";
      std::cout << "AA_Flag=" << (int)h.AA_Flag() << "\n";
      std::cout << "TC_Flag=" << (int)h.TC_Flag() << "\n";
      std::cout << "RD_Flag=" << (int)h.RD_Flag() << "\n";
      std::cout << "RA_Flag=" << (int)h.RA_Flag() << "\n";
      std::cout << "RCode="   << (int)h.RCode()   << "\n";
      std::cout << "OpCode="  << (int)h.OpCode()  << "\n";
      std::cout << "QdCount=" << (int)h.QdCount() << "\n";
      std::cout << "AnCount=" << (int)h.AnCount() << "\n";
      std::cout << "NsCount=" << (int)h.NsCount() << "\n";
      std::cout << "ArCount=" << (int)h.ArCount() << "\n";
   }
}
