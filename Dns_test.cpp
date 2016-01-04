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

using namespace std::string_literals;

template<class Y, class... Args>
auto make_my_unique(Args&&... args)
{
   union U
   {
      Y y;
      char storage[ sizeof(Y) ];

      U(Args&&... args)
      {
         for(auto& c : storage)
            c = 0xFF;

         new (&y) Y( std::forward<Args>(args)... );
      }

      ~U()
      {
         y.~Y();
      }
   };

   U* u = new U( std::forward<Args>(args)... );

   auto del = [u](Y *) { delete u; };

   return std::unique_ptr<Y, decltype(del)>( &(u->y), del );
}


BOOST_AUTO_TEST_CASE(DnsProtocol_Header)
{
   return;
   {
      auto p = make_my_unique<DnsProtocol::Header>();

      p->ID(0xf9ac);

      p->QR_Flag(0);
      p->OpCode(0);
      p->AA_Flag(0);
      p->TC_Flag(0);
      p->RD_Flag(1);
      p->RA_Flag(0);
      p->RCode(0);

      p->QdCount(1);
      p->AnCount(0);
      p->NsCount(0);
      p->ArCount(0);

      BOOST_CHECK_EQUAL(p->ID(), 0xf9ac);
      BOOST_CHECK_EQUAL(p->QR_Flag(), false);
      BOOST_CHECK_EQUAL(p->OpCode(), 0);
      BOOST_CHECK_EQUAL(p->AA_Flag(), false);
      BOOST_CHECK_EQUAL(p->TC_Flag(), false);
      BOOST_CHECK_EQUAL(p->RD_Flag(), true);
      BOOST_CHECK_EQUAL(p->RA_Flag(), false);
      BOOST_CHECK_EQUAL(p->ZCode(), 0);
      BOOST_CHECK_EQUAL(p->RCode(), 0);
      BOOST_CHECK_EQUAL(p->QdCount(), 1);
      BOOST_CHECK_EQUAL(p->AnCount(), 0);
      BOOST_CHECK_EQUAL(p->NsCount(), 0);
      BOOST_CHECK_EQUAL(p->ArCount(), 0);

      std::string req = "\xf9\xac\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\5yahoo\3com\0\0\17\0\1"s;
      req.resize(12);

      auto&& wd = p->Save();

      BOOST_CHECK_EQUAL( OctRep(wd), OctRep(req) );
   }

   {
      std::string res = "\xf9\xac\x81\x80\x00\x01\x00\x03\x00\x00\x00\x00\5yahoo\3com\0\0\17\0\1\300\f\0\17\0\1\0\0\4\245\0\31\0\1\4mta7\3am0\10yahoodns\3net\0\300\f\0\17\0\1\0\0\4\245\0\t\0\1\4mta6\300.\300\f\0\17\0\1\0\0\4\245\0\t\0\1\4mta5\300."s;

      auto p = make_my_unique<DnsProtocol::Header>( std::make_pair(res.data(), res.data() + res.size()) );

      BOOST_CHECK_EQUAL(p->ID(), 0xf9ac);
      BOOST_CHECK_EQUAL(p->QR_Flag(), true);
      BOOST_CHECK_EQUAL(p->OpCode(), 0);
      BOOST_CHECK_EQUAL(p->AA_Flag(), false);
      BOOST_CHECK_EQUAL(p->TC_Flag(), false);
      BOOST_CHECK_EQUAL(p->RD_Flag(), true);
      BOOST_CHECK_EQUAL(p->RA_Flag(), true);
      BOOST_CHECK_EQUAL(p->ZCode(), 0);
      BOOST_CHECK_EQUAL(p->RCode(), 0);
      BOOST_CHECK_EQUAL(p->QdCount(), 1);
      BOOST_CHECK_EQUAL(p->AnCount(), 3);
      BOOST_CHECK_EQUAL(p->NsCount(), 0);
      BOOST_CHECK_EQUAL(p->ArCount(), 0);
   }
}


BOOST_AUTO_TEST_CASE(DnsProtocol_QualifiedName)
{
   {
      DnsProtocol::QualifiedName qn;
      qn.Set("www.yahoo.com");

      auto&& wd = qn.Save();

      BOOST_CHECK_EQUAL(OctRep(wd), OctRep("\003www\005yahoo\003com\000"s));
      BOOST_CHECK_EQUAL(qn.Get(), "www.yahoo.com");

      {
         std::ostringstream oss;
         oss << qn;

         BOOST_CHECK_EQUAL(oss.str(), "[3]www[5]yahoo[3]com[0]");
      }
   }

   // below size limit
   {
      DnsProtocol::QualifiedName qn;
      qn.Set("yahooyahooyahooyahooyahooyahooyahooyahooyahooyahooyahooyahooyah.com");

      std::ostringstream oss;
      oss << qn;

      BOOST_CHECK_EQUAL(oss.str(), "[63]yahooyahooyahooyahooyahooyahooyahooyahooyahooyahooyahooyahooyah[3]com[0]");
   }

   // beyond size limit
   {
      DnsProtocol::QualifiedName qn;

      BOOST_CHECK_EXCEPTION(
            qn.Set("yahooyahooyahooyahooyahooyahooyahooyahooyahooyahooyahooyahooyahX.com"),
            DnsProtocol::bad_name,
            [](const auto& e) { return e.what() == "length too long"s; }
         );
   }

   // With ending dot
   {
      DnsProtocol::QualifiedName qn;

      qn.Set("www.yahoo.com.");

      auto&& wd = qn.Save();

      BOOST_CHECK_EQUAL(OctRep(wd), OctRep("\003www\005yahoo\003com\000"s));
      BOOST_CHECK_EQUAL(qn.Get(), "www.yahoo.com");
   }

   // With ending extra dots
   {
      DnsProtocol::QualifiedName qn;

      BOOST_CHECK_EXCEPTION(
            qn.Set("www.yahoo.com.."),
            DnsProtocol::bad_name,
            [](const auto& e) { return e.what() == "wrong format"s; }
         );
   }

   // With extra dots
   {
      DnsProtocol::QualifiedName qn;

      BOOST_CHECK_EXCEPTION(
            qn.Set("www.yahoo..com"),
            DnsProtocol::bad_name,
            [](const auto& e) { return e.what() == "wrong format"s; }
         );
   }

   // Load
   /*
   {
      std::string res = "\003www\005yahoo\003com\000"s;

      DnsProtocol::QualifiedName qn;
      
      qn.Load(std::make_pair(res.cbegin(), res.cend()));

      BOOST_CHECK_EQUAL(qn.Get(), "www.yahoo.com");
   }
   */
}


BOOST_AUTO_TEST_CASE(DnsProtocol_Question)
{
   return;
   {
      auto p = make_my_unique<DnsProtocol::Question>();

      p->QName("yahoo.com");
      p->QType(15);
      p->QClass(1);

      BOOST_CHECK_EQUAL(p->QName(), "yahoo.com");
      BOOST_CHECK_EQUAL(p->QType(), 15);
      BOOST_CHECK_EQUAL(p->QClass(), 1);

      std::string req = "\5yahoo\3com\x00\x00\x0f\x00\x01"s;
      req.resize(15);

      auto&& wd = p->Save();

      BOOST_CHECK_EQUAL( OctRep(wd), OctRep(req) );
   }

   /*
   {
      std::string res = "\x05yahoo\x03com\x00\x00\x0f\x00\x01"s;

      auto p = make_my_unique<DnsProtocol::Question>();
      
      p->Load( std::make_pair(res.data(), res.data() + res.size()) );

      BOOST_CHECK_EQUAL(p->QName(), "yahoo.com");
      BOOST_CHECK_EQUAL(p->QType(), 15);
      BOOST_CHECK_EQUAL(p->QClass(), 1);
   }
   */
}
