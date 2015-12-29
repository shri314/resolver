#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE Dns_test
#include <boost/test/unit_test.hpp>

#include "Dns.h"

#include <string>
#include <sstream>
#include <iostream>

std::string HexRep(unsigned char x, bool keep_printables = false)
{
   std::ostringstream oss;

   if( keep_printables && std::isprint(x) && !std::isspace(x) )
      oss << x;
   else
   {
      if(x < 16)
         oss << "\\x0" << std::hex << (unsigned)x;
      else
         oss << "\\x" << std::hex << (unsigned)x;
   }

   return oss.str();
}

std::string HexRep(const std::vector<uint8_t>& data)
{
   std::ostringstream oss;
   for(auto x : data)
      oss << HexRep((unsigned char)x);

   return oss.str();
}

std::string HexRep(const std::string& data)
{
   std::ostringstream oss;
   for(auto x : data)
      oss << HexRep((unsigned char)x);

   return oss.str();
}

std::string HexRep(uint32_t x)
{
   unsigned char* b = reinterpret_cast<unsigned char*>(&x);
   return HexRep(std::string(b, b + sizeof(x)));
}

std::string HexRep(uint16_t x)
{
   unsigned char* b = reinterpret_cast<unsigned char*>(&x);
   return HexRep(std::string(b, b + sizeof(x)));
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

      BOOST_CHECK_EQUAL( HexRep(wd), HexRep("\003www\005yahoo\003com\000"s) );
   }

   {
      DnsProtocol::HeaderPod h;
      h.ID(0xf9ac);

      h.QR_Flag(0);
      h.OpCode(0);
      h.AA_Flag(0);
      h.TC_Flag(0);
      h.RD_Flag(1);
      h.RA_Flag(0);
      h.RCode(0);

      h.QdCount(1);
      h.AnCount(0);
      h.NsCount(0);
      h.ArCount(0);

      auto&& wd = h.WireData();

      BOOST_CHECK_EQUAL(h.ID(), 0xf9ac);
      BOOST_CHECK_EQUAL(h.QR_Flag(), false);
      BOOST_CHECK_EQUAL(h.OpCode(), 0);
      BOOST_CHECK_EQUAL(h.AA_Flag(), false);
      BOOST_CHECK_EQUAL(h.TC_Flag(), false);
      BOOST_CHECK_EQUAL(h.RD_Flag(), true);
      BOOST_CHECK_EQUAL(h.RA_Flag(), false);
      BOOST_CHECK_EQUAL(h.ZCode(), 0);
      BOOST_CHECK_EQUAL(h.RCode(), 0);
      BOOST_CHECK_EQUAL(h.QdCount(), 1);
      BOOST_CHECK_EQUAL(h.AnCount(), 0);
      BOOST_CHECK_EQUAL(h.NsCount(), 0);
      BOOST_CHECK_EQUAL(h.ArCount(), 0);

      std::string req = "\xf9\xac\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\5yahoo\3com\0\0\17\0\1"s;
      req.resize(12);

      BOOST_CHECK_EQUAL( HexRep(wd), HexRep(req) );
   }

   {
      std::string res = "\xf9\xac\x81\x80\x00\x01\x00\x03\x00\x00\x00\x00\5yahoo\3com\0\0\17\0\1\300\f\0\17\0\1\0\0\4\245\0\31\0\1\4mta7\3am0\10yahoodns\3net\0\300\f\0\17\0\1\0\0\4\245\0\t\0\1\4mta6\300.\300\f\0\17\0\1\0\0\4\245\0\t\0\1\4mta5\300."s;

      DnsProtocol::HeaderPod h( std::make_pair(res.data(), res.data() + res.size()) );

      BOOST_CHECK_EQUAL(h.ID(), 0xf9ac);
      BOOST_CHECK_EQUAL(h.QR_Flag(), true);
      BOOST_CHECK_EQUAL(h.OpCode(), 0);
      BOOST_CHECK_EQUAL(h.AA_Flag(), false);
      BOOST_CHECK_EQUAL(h.TC_Flag(), false);
      BOOST_CHECK_EQUAL(h.RD_Flag(), true);
      BOOST_CHECK_EQUAL(h.RA_Flag(), true);
      BOOST_CHECK_EQUAL(h.ZCode(), 0);
      BOOST_CHECK_EQUAL(h.RCode(), 0);
      BOOST_CHECK_EQUAL(h.QdCount(), 1);
      BOOST_CHECK_EQUAL(h.AnCount(), 3);
      BOOST_CHECK_EQUAL(h.NsCount(), 0);
      BOOST_CHECK_EQUAL(h.ArCount(), 0);
   }
}
