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
   // Save
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

   // Load
   {
      std::string res = "\xf9\xac\x81\x80\x00\x01\x00\x03\x00\x00\x00\x00\5yahoo\3com\0\0\17\0\1\300\f\0\17\0\1\0\0\4\245\0\31\0\1\4mta7\3am0\10yahoodns\3net\0\300\f\0\17\0\1\0\0\4\245\0\t\0\1\4mta6\300.\300\f\0\17\0\1\0\0\4\245\0\t\0\1\4mta5\300."s;
      auto&& begin = res.cbegin();

      auto p = make_my_unique<DnsProtocol::Header>();

      p->Load( begin, res.cend() );

      BOOST_CHECK_EQUAL( std::distance(res.cbegin(), begin), 12 );

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

   // Load with truncated data
   {
      std::string res = "\xf9\xac\x81\x80\x00\x01\x00\x03";
      auto&& begin = res.cbegin();

      auto p = make_my_unique<DnsProtocol::Header>();

      BOOST_CHECK_EXCEPTION(
            p->Load( begin, res.cend() ),
            DnsProtocol::bad_data_stream,
            [](const auto& e) { return e.what() == "truncated"s; }
         );
   }
}


BOOST_AUTO_TEST_CASE(DnsProtocol_QualifiedName)
{
   {
      DnsProtocol::QualifiedName qn;
      BOOST_CHECK_EQUAL(qn.Get(), "");
   }

   // below 63 label limit
   {
      DnsProtocol::QualifiedName qn;
      qn.Set("www.initial.com");
      BOOST_CHECK_EQUAL(qn.Get(), "www.initial.com");

      std::string req = std::string(63, 'w') + ".com";
      qn.Set(req);

      std::ostringstream oss;
      oss << qn;

      BOOST_CHECK_EQUAL(qn.Get(), req);
      BOOST_CHECK_EQUAL(oss.str(), req);
   }

   // beyond 63 label limit
   {
      DnsProtocol::QualifiedName qn;
      qn.Set("www.initial.com");
      BOOST_CHECK_EQUAL(qn.Get(), "www.initial.com");

      BOOST_CHECK_EXCEPTION(
            qn.Set(std::string(63, 'w') + "X.com"),
            DnsProtocol::bad_name,
            [](const auto& e) { return e.what() == "length too long"s; }
         );

      BOOST_CHECK_EQUAL(qn.Get(), "www.initial.com");
   }

   // below 255 limit
   {
      DnsProtocol::QualifiedName qn;
      qn.Set("www.initial.com");
      BOOST_CHECK_EQUAL(qn.Get(), "www.initial.com");

      std::string res = std::string(077, 'w') + '.' + std::string(077, 'a') + '.' + std::string(077, 'b') + '.' + std::string(075, 'c');

      qn.Set(res);

      BOOST_CHECK_EQUAL( qn.Get(), res );
   }

   // beyond 255 limit
   {
      DnsProtocol::QualifiedName qn;
      qn.Set("www.initial.com");
      BOOST_CHECK_EQUAL(qn.Get(), "www.initial.com");

      std::string res = std::string(077, 'w') + '.' + std::string(077, 'a') + '.' + std::string(077, 'b') + '.' + std::string(075, 'c');

      BOOST_CHECK_EXCEPTION(
            qn.Set(res + "X"),
            DnsProtocol::bad_name,
            [](const auto& e) { return e.what() == "length too long"s; }
         );

      BOOST_CHECK_EQUAL(qn.Get(), "www.initial.com");
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
      qn.Set("www.initial.com");
      BOOST_CHECK_EQUAL(qn.Get(), "www.initial.com");

      BOOST_CHECK_EXCEPTION(
            qn.Set("www.yahoo.com.."),
            DnsProtocol::bad_name,
            [](const auto& e) { return e.what() == "wrong format"s; }
         );

      BOOST_CHECK_EQUAL( qn.Get(), "www.initial.com" );
   }

   // With extra dots
   {
      DnsProtocol::QualifiedName qn;
      qn.Set("www.initial.com");
      BOOST_CHECK_EQUAL(qn.Get(), "www.initial.com");

      BOOST_CHECK_EXCEPTION(
            qn.Set("www.yahoo..com"),
            DnsProtocol::bad_name,
            [](const auto& e) { return e.what() == "wrong format"s; }
         );

      BOOST_CHECK_EQUAL( qn.Get(), "www.initial.com" );
   }

   // Save
   {
      DnsProtocol::QualifiedName qn;
      qn.Set("www.yahoo.com");

      auto&& wd = qn.Save();

      BOOST_CHECK_EQUAL(OctRep(wd), OctRep("\003www\005yahoo\003com\000"s));
      BOOST_CHECK_EQUAL(qn.Get(), "www.yahoo.com");

      {
         std::ostringstream oss;
         oss << qn;

         BOOST_CHECK_EQUAL(oss.str(), "www.yahoo.com");
      }
   }

   // Load
   {
      std::string res = "\3www\5yahoo\3com\0ABCDEFGHIJKLMNOPQRSTUVWXYZ"s;
      auto&& begin = res.cbegin();

      DnsProtocol::QualifiedName qn;
      qn.Set("www.initial.com");
      BOOST_CHECK_EQUAL(qn.Get(), "www.initial.com");
      
      qn.Load(begin, res.cend());

      BOOST_CHECK_EQUAL( std::distance(res.cbegin(), begin), 15 );
      BOOST_CHECK( begin != res.cend() && *begin == 'A' );
      BOOST_CHECK_EQUAL(qn.Get(), "www.yahoo.com");
   }

   // Load within exactly supported length of 255
   {
      std::string res = 
         "\77"s + std::string(077, 'w') +
         "\77"s + std::string(077, 'a') +
         "\77"s + std::string(077, 'b') +
         "\75"s + std::string(075, 'c') + "\0"s;

      auto&& begin = res.cbegin();

      DnsProtocol::QualifiedName qn;
      qn.Set("www.initial.com");
      BOOST_CHECK_EQUAL(qn.Get(), "www.initial.com");
      
      qn.Load(begin, res.cend());

      BOOST_CHECK_EQUAL(qn.Get(), std::string(077, 'w') + '.' + std::string(077, 'a') + '.' + std::string(077, 'b') + '.' + std::string(075, 'c'));
   }

   // Load with bad length in data > 255
   {
      std::string res = 
         "\77"s + std::string(077, 'w') +
         "\77"s + std::string(077, 'a') +
         "\77"s + std::string(077, 'b') +
         "\76"s + std::string(076, 'c') + "\0"s;

      auto&& begin = res.cbegin();

      DnsProtocol::QualifiedName qn;
      qn.Set("www.initial.com");
      BOOST_CHECK_EQUAL(qn.Get(), "www.initial.com");
      
      BOOST_CHECK_EXCEPTION(
            qn.Load(begin, res.cend()),
            DnsProtocol::bad_data_stream,
            [](const auto& e) { return e.what() == "length too long"s; }
         );

      BOOST_CHECK_EQUAL(qn.Get(), "www.initial.com");
   }

   // Load with bad length in data (label > 63)
   {
      std::string res = "\100www\005yahoo\003com\000zZ"s;
      auto&& begin = res.cbegin();

      DnsProtocol::QualifiedName qn;
      qn.Set("www.initial.com");
      BOOST_CHECK_EQUAL(qn.Get(), "www.initial.com");
      
      BOOST_CHECK_EXCEPTION(
            qn.Load(begin, res.cend()),
            DnsProtocol::bad_data_stream,
            [](const auto& e) { return e.what() == "length too long"s; }
         );

      BOOST_CHECK_EQUAL(qn.Get(), "www.initial.com");
   }

   // Load with bad length in data (label > 63)
   {
      std::string res = "\003www\100yahoo\003com\000zZ"s;
      auto&& begin = res.cbegin();

      DnsProtocol::QualifiedName qn;
      qn.Set("www.initial.com");
      BOOST_CHECK_EQUAL(qn.Get(), "www.initial.com");
      
      BOOST_CHECK_EXCEPTION(
            qn.Load(begin, res.cend()),
            DnsProtocol::bad_data_stream,
            [](const auto& e) { return e.what() == "length too long"s; }
         );

      BOOST_CHECK_EQUAL(qn.Get(), "www.initial.com");
   }

   // Load with truncated data
   {
      std::string res = "\003www\005ya"s;
      auto&& begin = res.cbegin();

      DnsProtocol::QualifiedName qn;
      qn.Set("www.initial.com");
      BOOST_CHECK_EQUAL(qn.Get(), "www.initial.com");
      
      BOOST_CHECK_EXCEPTION(
            qn.Load(begin, res.cend()),
            DnsProtocol::bad_data_stream,
            [](const auto& e) { return e.what() == "truncated"s; }
         );

      BOOST_CHECK_EQUAL(qn.Get(), "www.initial.com");
   }

   // Load with truncated data (not ending with \0)
   {
      std::string res = "\003www"s;
      auto&& begin = res.cbegin();

      DnsProtocol::QualifiedName qn;
      qn.Set("www.initial.com");
      BOOST_CHECK_EQUAL(qn.Get(), "www.initial.com");
      
      BOOST_CHECK_EXCEPTION(
            qn.Load(begin, res.cend()),
            DnsProtocol::bad_data_stream,
            [](const auto& e) { return e.what() == "truncated"s; }
         );

      BOOST_CHECK_EQUAL(qn.Get(), "www.initial.com");
   }
}


BOOST_AUTO_TEST_CASE(DnsProtocol_Question)
{
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

   // Load
   {
      std::string res = "\5yahoo\3com\x00\x00\x0f\x00\x01"s;
      auto&& begin = res.cbegin();

      auto p = make_my_unique<DnsProtocol::Question>();

      p->Load( begin, res.cend() );

      BOOST_CHECK_EQUAL(p->QName(), "yahoo.com");
      BOOST_CHECK_EQUAL(p->QType(), 15);
      BOOST_CHECK_EQUAL(p->QClass(), 1);
   }
}
