#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE Dns_test
#include <boost/test/unit_test.hpp>

#include "Dns.h"

#include "test_context.h"

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
auto make_my_unique(Args&& ... args)
{
   union U
   {
      Y y;
      char storage[ sizeof(Y) ];

      U(Args&& ... args)
      {
         for(auto& c : storage)
            c = 0xFF;

         new(&y) Y(std::forward<Args>(args)...);
      }

      ~U()
      {
         y.~Y();
      }
   };

   U* u = new U(std::forward<Args>(args)...);

   auto del = [u](Y*) { delete u; };

   return std::unique_ptr<Y, decltype(del)>(&(u->y), del);
}

struct exception_info_t
{
      std::string type;
      std::string str;
      int code;

   public:
      exception_info_t() = default;

      exception_info_t(const std::string& type, const std::string& str, int code)
         : type(type)
         , str(str)
         , code(code)
      {
      }

      explicit operator bool() const
      {
         return !type.empty();
      }

      template<class ET>
      bool operator()(const ET& e)
      {
         BOOST_CHECK_EQUAL(typeid(e).name(), type);
         BOOST_CHECK_EQUAL(e.what(), str);

         if(auto f = dynamic_cast<const DnsProtocol::bad_name*>(&e))
         {
            BOOST_CHECK_EQUAL(f->code(), code);
            return true;
         }

         if(auto f = dynamic_cast<const DnsProtocol::bad_data_stream*>(&e))
         {
            BOOST_CHECK_EQUAL(f->code(), code);
            return true;
         }
      }
};


template<class ET>
exception_info_t exception_info(const std::string& str, int code)
{
   return exception_info_t{ typeid(ET).name(), str, code };
}

exception_info_t exception_info()
{
   return exception_info_t{};
}


BOOST_AUTO_TEST_CASE(DnsProtocol_Header_Save)
{
   struct
   {
      std::string test_context;

      uint16_t input_ID;

      bool input_QR_Flag;
      bool input_AA_Flag;
      bool input_TC_Flag;
      bool input_RD_Flag;
      bool input_RA_Flag;

      uint16_t input_OpCode;
      uint16_t input_RCode;

      uint16_t input_QdCount;
      uint16_t input_AnCount;
      uint16_t input_NsCount;
      uint16_t input_ArCount;

      std::string expected_raw_data;
      std::string expected_stream;
   }
   TestData[] =
   {
      {
         TEST_CONTEXT("query header"),

         /* ID */ 0xf9ac,
         /* QR_Flag */ false, /* AA_Flag */ false, /* TC_Flag */ false, /* RD_Flag */ false, /* RA_Flag */ false,
         /* OpCode */ 0, /* RCode */ 0,
         /* QdCount */ 1, /* AnCount */ 0, /* NsCount */ 0, /* ArCount */ 0,

         "\xf9\xac\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"s,
         "{ ID=63916, Flags=[QRY], OpCode=0, RCode=0, QdCount=1, AnCount=0, NsCount=0, ArCount=0 }",
      },

      {
         TEST_CONTEXT("response header"),

         /* ID */ 0x5006,
         /* QR_Flag */ true, /* AA_Flag */ false, /* TC_Flag */ false, /* RD_Flag */ false, /* RA_Flag */ false,
         /* OpCode */ 0, /* RCode */ 0,
         /* QdCount */ 0, /* AnCount */ 1, /* NsCount */ 0, /* ArCount */ 0,

         "\x50\x06\x80\x00\x00\x00\x00\x01\x00\x00\x00\x00"s,
         "{ ID=20486, Flags=[RES], OpCode=0, RCode=0, QdCount=0, AnCount=1, NsCount=0, ArCount=0 }",
      },

      {
         TEST_CONTEXT("response header with RCode"),

         /* ID */ 0x5006,
         /* QR_Flag */ true, /* AA_Flag */ false, /* TC_Flag */ false, /* RD_Flag */ false, /* RA_Flag */ false,
         /* OpCode */ 0, /* RCode */ 9,
         /* QdCount */ 0, /* AnCount */ 1, /* NsCount */ 0, /* ArCount */ 0,

         "\x50\x06\x80\x09\x00\x00\x00\x01\x00\x00\x00\x00"s,
         "{ ID=20486, Flags=[RES], OpCode=0, RCode=9, QdCount=0, AnCount=1, NsCount=0, ArCount=0 }",
      },

      {
         TEST_CONTEXT("query header with RD"),

         /* ID */ 0xf9ac,
         /* QR_Flag */ false, /* AA_Flag */ false, /* TC_Flag */ false, /* RD_Flag */ true, /* RA_Flag */ false,
         /* OpCode */ 0, /* RCode */ 0,
         /* QdCount */ 1, /* AnCount */ 0, /* NsCount */ 0, /* ArCount */ 0,

         "\xf9\xac\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"s,
         "{ ID=63916, Flags=[QRY,RD], OpCode=0, RCode=0, QdCount=1, AnCount=0, NsCount=0, ArCount=0 }",
      },

      {
         TEST_CONTEXT("query header with OpCode"),

         /* ID */ 0xf9ac,
         /* QR_Flag */ false, /* AA_Flag */ false, /* TC_Flag */ false, /* RD_Flag */ false, /* RA_Flag */ false,
         /* OpCode */ 0xf, /* RCode */ 0,
         /* QdCount */ 1, /* AnCount */ 0, /* NsCount */ 0, /* ArCount */ 0,

         "\xf9\xac\x78\x00\x00\x01\x00\x00\x00\x00\x00\x00"s,
         "{ ID=63916, Flags=[QRY], OpCode=15, RCode=0, QdCount=1, AnCount=0, NsCount=0, ArCount=0 }",
      },

      {
         TEST_CONTEXT("response header with AA"),

         /* ID */ 0x1111,
         /* QR_Flag */ true, /* AA_Flag */ true, /* TC_Flag */ false, /* RD_Flag */ false, /* RA_Flag */ false,
         /* OpCode */ 0, /* RCode */ 0,
         /* QdCount */ 0, /* AnCount */ 0, /* NsCount */ 1, /* ArCount */ 0,

         "\x11\x11\x84\x00\x00\x00\x00\x00\x00\x01\x00\x00"s,
         "{ ID=4369, Flags=[RES,AA], OpCode=0, RCode=0, QdCount=0, AnCount=0, NsCount=1, ArCount=0 }",
      },

      {
         TEST_CONTEXT("response header with TC"),

         /* ID */ 0xFFFF,
         /* QR_Flag */ true, /* AA_Flag */ false, /* TC_Flag */ true, /* RD_Flag */ false, /* RA_Flag */ false,
         /* OpCode */ 0, /* RCode */ 0,
         /* QdCount */ 0, /* AnCount */ 0, /* NsCount */ 0, /* ArCount */ 1,

         "\xFF\xFF\x82\x00\x00\x00\x00\x00\x00\x00\x00\x01"s,
         "{ ID=65535, Flags=[RES,TC], OpCode=0, RCode=0, QdCount=0, AnCount=0, NsCount=0, ArCount=1 }",
      },

      {
         TEST_CONTEXT("response header with RA"),

         /* ID */ 0xFFFF,
         /* QR_Flag */ true, /* AA_Flag */ false, /* TC_Flag */ false, /* RD_Flag */ false, /* RA_Flag */ true,
         /* OpCode */ 0, /* RCode */ 0,
         /* QdCount */ 0, /* AnCount */ 0, /* NsCount */ 0, /* ArCount */ 1,

         "\xFF\xFF\x80\x80\x00\x00\x00\x00\x00\x00\x00\x01"s,
         "{ ID=65535, Flags=[RES,RA], OpCode=0, RCode=0, QdCount=0, AnCount=0, NsCount=0, ArCount=1 }",
      },
   };

   /////////////////////////////////////////////////////

   for(auto Datum : TestData)
   {
      BOOST_TEST_CONTEXT(Datum.test_context)
      {
         auto pH = make_my_unique<DnsProtocol::Header>(); // TEST OBJECT

         /// Set
         {
            pH->ID(Datum.input_ID);
            pH->QR_Flag(Datum.input_QR_Flag);
            pH->AA_Flag(Datum.input_AA_Flag);
            pH->TC_Flag(Datum.input_TC_Flag);
            pH->RD_Flag(Datum.input_RD_Flag);
            pH->RA_Flag(Datum.input_RA_Flag);

            pH->OpCode(Datum.input_OpCode);
            pH->RCode(Datum.input_RCode);

            pH->QdCount(Datum.input_QdCount);
            pH->AnCount(Datum.input_AnCount);
            pH->NsCount(Datum.input_NsCount);
            pH->ArCount(Datum.input_ArCount);
         }

         /// Check
         {
            BOOST_CHECK_EQUAL(pH->ID(),      Datum.input_ID);

            BOOST_CHECK_EQUAL(pH->QR_Flag(), Datum.input_QR_Flag);
            BOOST_CHECK_EQUAL(pH->AA_Flag(), Datum.input_AA_Flag);
            BOOST_CHECK_EQUAL(pH->TC_Flag(), Datum.input_TC_Flag);
            BOOST_CHECK_EQUAL(pH->RD_Flag(), Datum.input_RD_Flag);
            BOOST_CHECK_EQUAL(pH->RA_Flag(), Datum.input_RA_Flag);

            BOOST_CHECK_EQUAL(pH->OpCode(),  Datum.input_OpCode);
            BOOST_CHECK_EQUAL(pH->RCode(),   Datum.input_RCode);
            BOOST_CHECK_EQUAL(pH->ZCode(),   0);

            BOOST_CHECK_EQUAL(pH->QdCount(), Datum.input_QdCount);
            BOOST_CHECK_EQUAL(pH->AnCount(), Datum.input_AnCount);
            BOOST_CHECK_EQUAL(pH->NsCount(), Datum.input_NsCount);
            BOOST_CHECK_EQUAL(pH->ArCount(), Datum.input_ArCount);
         }

         {
            BOOST_CHECK_NO_THROW(BOOST_CHECK_EQUAL(OctRep(pH->Save()), OctRep(Datum.expected_raw_data))); // TEST

            BOOST_CHECK_NO_THROW(BOOST_CHECK_EQUAL(static_cast<std::ostringstream&>(std::ostringstream() << *pH).str(), Datum.expected_stream));
         }
      }
   }
}


BOOST_AUTO_TEST_CASE(DnsProtocol_Header_Load)
{
   struct
   {
      std::string test_context;

      std::string input_raw_data;

      exception_info_t expected_exception;

      int expected_distance;

      std::string expected_stream;

      uint16_t expected_ID;

      bool expected_QR_Flag;
      bool expected_AA_Flag;
      bool expected_TC_Flag;
      bool expected_RD_Flag;
      bool expected_RA_Flag;

      uint16_t expected_OpCode;
      uint16_t expected_RCode;

      uint16_t expected_QdCount;
      uint16_t expected_AnCount;
      uint16_t expected_NsCount;
      uint16_t expected_ArCount;
   }
   TestData[] =
   {
      {
         TEST_CONTEXT("Load query header"),
         "\xf9\xac\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"s,

         exception_info(),
         12,
         "{ ID=63916, Flags=[QRY], OpCode=0, RCode=0, QdCount=1, AnCount=0, NsCount=0, ArCount=0 }",

         /* ID */ 0xf9ac,
         /* QR_Flag */ false, /* AA_Flag */ false, /* TC_Flag */ false, /* RD_Flag */ false, /* RA_Flag */ false,
         /* OpCode */ 0, /* RCode */ 0,
         /* QdCount */ 1, /* AnCount */ 0, /* NsCount */ 0, /* ArCount */ 0,
      },

      {
         TEST_CONTEXT("Load query header (with data beyond header)"),
         "\xf9\xac\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00ZABCDEFGHIJKLMNOP"s,

         exception_info(),
         12,
         "{ ID=63916, Flags=[QRY], OpCode=0, RCode=0, QdCount=1, AnCount=0, NsCount=0, ArCount=0 }",

         /* ID */ 0xf9ac,
         /* QR_Flag */ false, /* AA_Flag */ false, /* TC_Flag */ false, /* RD_Flag */ false, /* RA_Flag */ false,
         /* OpCode */ 0, /* RCode */ 0,
         /* QdCount */ 1, /* AnCount */ 0, /* NsCount */ 0, /* ArCount */ 0,
      },

      {
         TEST_CONTEXT("Load response header"),
         "\x50\x06\x80\x00\x00\x00\x00\x01\x00\x00\x00\x00"s,

         exception_info(),
         12,
         "{ ID=20486, Flags=[RES], OpCode=0, RCode=0, QdCount=0, AnCount=1, NsCount=0, ArCount=0 }",

         /* ID */ 0x5006,
         /* QR_Flag */ true, /* AA_Flag */ false, /* TC_Flag */ false, /* RD_Flag */ false, /* RA_Flag */ false,
         /* OpCode */ 0, /* RCode */ 0,
         /* QdCount */ 0, /* AnCount */ 1, /* NsCount */ 0, /* ArCount */ 0,
      },

      {
         TEST_CONTEXT("Load response header (with data beyond header)"),
         "\x50\x06\x80\x00\x00\x00\x00\x01\x00\x00\x00\x00ZABCDEFGHIJKLMNOP"s,

         exception_info(),
         12,
         "{ ID=20486, Flags=[RES], OpCode=0, RCode=0, QdCount=0, AnCount=1, NsCount=0, ArCount=0 }",

         /* ID */ 0x5006,
         /* QR_Flag */ true, /* AA_Flag */ false, /* TC_Flag */ false, /* RD_Flag */ false, /* RA_Flag */ false,
         /* OpCode */ 0, /* RCode */ 0,
         /* QdCount */ 0, /* AnCount */ 1, /* NsCount */ 0, /* ArCount */ 0,
      },

      {
         TEST_CONTEXT("Load a truncated response header"),
         "\x50\x06\x80\x00\x00\x00\x00\x01\x00\x00\x00"s,

         exception_info<DnsProtocol::bad_data_stream>("truncated"s, 1),
         11,
         "",
      },

      {
         TEST_CONTEXT("Load response header with RCode"),
         "\x50\x06\x80\x09\x00\x00\x00\x01\x00\x00\x00\x00ZABCDEFGHIJKLMNOP"s,

         exception_info(),
         12,
         "{ ID=20486, Flags=[RES], OpCode=0, RCode=9, QdCount=0, AnCount=1, NsCount=0, ArCount=0 }",

         /* ID */ 0x5006,
         /* QR_Flag */ true, /* AA_Flag */ false, /* TC_Flag */ false, /* RD_Flag */ false, /* RA_Flag */ false,
         /* OpCode */ 0, /* RCode */ 9,
         /* QdCount */ 0, /* AnCount */ 1, /* NsCount */ 0, /* ArCount */ 0,
      },

      {
         TEST_CONTEXT("Load query header with RD"),
         "\xf9\xac\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00ZABCDEFGHIJKLMNOP"s,

         exception_info(),
         12,
         "{ ID=63916, Flags=[QRY,RD], OpCode=0, RCode=0, QdCount=1, AnCount=0, NsCount=0, ArCount=0 }",

         /* ID */ 0xf9ac,
         /* QR_Flag */ false, /* AA_Flag */ false, /* TC_Flag */ false, /* RD_Flag */ true, /* RA_Flag */ false,
         /* OpCode */ 0, /* RCode */ 0,
         /* QdCount */ 1, /* AnCount */ 0, /* NsCount */ 0, /* ArCount */ 0,
      },

      {
         TEST_CONTEXT("Load query header with OpCode"),
         "\xf9\xac\x78\x00\x00\x01\x00\x00\x00\x00\x00\x00ZABCDEFGHIJKLMNOP"s,

         exception_info(),
         12,
         "{ ID=63916, Flags=[QRY], OpCode=15, RCode=0, QdCount=1, AnCount=0, NsCount=0, ArCount=0 }",

         /* ID */ 0xf9ac,
         /* QR_Flag */ false, /* AA_Flag */ false, /* TC_Flag */ false, /* RD_Flag */ false, /* RA_Flag */ false,
         /* OpCode */ 0xf, /* RCode */ 0,
         /* QdCount */ 1, /* AnCount */ 0, /* NsCount */ 0, /* ArCount */ 0,
      },

      {
         TEST_CONTEXT("Load response header with AA"),
         "\x11\x11\x84\x00\x00\x00\x00\x00\x00\x01\x00\x00ZABCDEFGHIJKLMNOP"s,

         exception_info(),
         12,
         "{ ID=4369, Flags=[RES,AA], OpCode=0, RCode=0, QdCount=0, AnCount=0, NsCount=1, ArCount=0 }",

         /* ID */ 0x1111,
         /* QR_Flag */ true, /* AA_Flag */ true, /* TC_Flag */ false, /* RD_Flag */ false, /* RA_Flag */ false,
         /* OpCode */ 0, /* RCode */ 0,
         /* QdCount */ 0, /* AnCount */ 0, /* NsCount */ 1, /* ArCount */ 0,
      },

      {
         TEST_CONTEXT("Load response header with TC"),
         "\xFF\xFF\x82\x00\x00\x00\x00\x00\x00\x00\x00\x01ZABCDEFGHIJKLMNOP"s,

         exception_info(),
         12,
         "{ ID=65535, Flags=[RES,TC], OpCode=0, RCode=0, QdCount=0, AnCount=0, NsCount=0, ArCount=1 }",

         /* ID */ 0xFFFF,
         /* QR_Flag */ true, /* AA_Flag */ false, /* TC_Flag */ true, /* RD_Flag */ false, /* RA_Flag */ false,
         /* OpCode */ 0, /* RCode */ 0,
         /* QdCount */ 0, /* AnCount */ 0, /* NsCount */ 0, /* ArCount */ 1,
      },

      {
         TEST_CONTEXT("Load response header with RA"),
         "\xFF\xFF\x80\x80\x00\x00\x00\x00\x00\x00\x00\x01ZABCDEFGHIJKLMNOP"s,

         exception_info(),
         12,
         "{ ID=65535, Flags=[RES,RA], OpCode=0, RCode=0, QdCount=0, AnCount=0, NsCount=0, ArCount=1 }",

         /* ID */ 0xFFFF,
         /* QR_Flag */ true, /* AA_Flag */ false, /* TC_Flag */ false, /* RD_Flag */ false, /* RA_Flag */ true,
         /* OpCode */ 0, /* RCode */ 0,
         /* QdCount */ 0, /* AnCount */ 0, /* NsCount */ 0, /* ArCount */ 1,
      },
   };

   /////////////////////////////////////////////////////

   for(auto Datum : TestData)
   {
      BOOST_TEST_CONTEXT(Datum.test_context)
      {
         auto pH = make_my_unique<DnsProtocol::Header>(); // TEST OBJECT

         /// Set
         {
            pH->ID(0xFFFF);
            pH->QR_Flag(true);
            pH->AA_Flag(true);
            pH->TC_Flag(true);
            pH->RD_Flag(true);
            pH->RA_Flag(true);

            pH->OpCode(0xFFFF);
            pH->RCode(0xFFFF);

            pH->QdCount(0xFFFF);
            pH->AnCount(0xFFFF);
            pH->NsCount(0xFFFF);
            pH->ArCount(0xFFFF);
         }

         if(Datum.expected_exception)
         {
            auto&& b = Datum.input_raw_data.begin();
            auto&& e = Datum.input_raw_data.end();

            BOOST_CHECK_EXCEPTION(pH->Load(b, e), std::exception, Datum.expected_exception); // THE TEST

            BOOST_CHECK(0 <= std::distance(Datum.input_raw_data.begin(), b) && std::distance(Datum.input_raw_data.begin(), b) <= Datum.expected_distance);
         }
         else
         {
            auto&& b = Datum.input_raw_data.begin();
            auto&& e = Datum.input_raw_data.end();

            BOOST_CHECK_NO_THROW(pH->Load(b, e)); // THE TEST

            BOOST_CHECK_EQUAL(std::distance(Datum.input_raw_data.begin(), b), Datum.expected_distance);

            BOOST_CHECK_NO_THROW(BOOST_CHECK_EQUAL(OctRep(pH->Save()), OctRep(Datum.input_raw_data.substr(0, Datum.expected_distance))));

            BOOST_CHECK_NO_THROW(BOOST_CHECK_EQUAL(static_cast<std::ostringstream&>(std::ostringstream() << *pH).str(), Datum.expected_stream));

            // More Check
            {
               BOOST_CHECK_EQUAL(pH->ID(),      Datum.expected_ID);

               BOOST_CHECK_EQUAL(pH->QR_Flag(), Datum.expected_QR_Flag);
               BOOST_CHECK_EQUAL(pH->AA_Flag(), Datum.expected_AA_Flag);
               BOOST_CHECK_EQUAL(pH->TC_Flag(), Datum.expected_TC_Flag);
               BOOST_CHECK_EQUAL(pH->RD_Flag(), Datum.expected_RD_Flag);
               BOOST_CHECK_EQUAL(pH->RA_Flag(), Datum.expected_RA_Flag);

               BOOST_CHECK_EQUAL(pH->OpCode(),  Datum.expected_OpCode);
               BOOST_CHECK_EQUAL(pH->RCode(),   Datum.expected_RCode);
               BOOST_CHECK_EQUAL(pH->ZCode(),   0);

               BOOST_CHECK_EQUAL(pH->QdCount(), Datum.expected_QdCount);
               BOOST_CHECK_EQUAL(pH->AnCount(), Datum.expected_AnCount);
               BOOST_CHECK_EQUAL(pH->NsCount(), Datum.expected_NsCount);
               BOOST_CHECK_EQUAL(pH->ArCount(), Datum.expected_ArCount);
            }
         }
      }
   }
}


BOOST_AUTO_TEST_CASE(DnsProtocol_QualifiedName_Save)
{
   struct
   {
      std::string test_context;
      std::string input_name;

      exception_info_t expected_exception;
      std::string expected_name;
      std::string expected_raw_data;
   }
   TestData[] =
   {
      {
         TEST_CONTEXT("empty"),
         "",

         exception_info(),
         "",
         "\0"s,
      },

      {
         TEST_CONTEXT("simple case"),
         "www.yahoo.com",

         exception_info(),
         "www.yahoo.com",
         "\3www\5yahoo\3com\0"s,
      },

      {
         TEST_CONTEXT("with single ending dot"),
         "www.yahoo.com.",

         exception_info(),
         "www.yahoo.com",
         "\3www\5yahoo\3com\0"s,
      },

      {
         TEST_CONTEXT("with extra ending dots"),
         "www.yahoo.com..",

         exception_info<DnsProtocol::bad_name>("wrong format"s, 1),
         "",
         "",
      },

      {
         TEST_CONTEXT("with extra dots"),
         "www.yahoo..com",

         exception_info<DnsProtocol::bad_name>("wrong format"s, 1),
         "",
         "",
      },

      {
         TEST_CONTEXT("below 63 label limit"),
         std::string(63, 'w') + ".com",

         exception_info(),
         std::string(63, 'w') + ".com",
         "\77"s + std::string(63, 'w') + "\3com\0"s,
      },

      {
         TEST_CONTEXT("beyond 63 label limit"),
         std::string(63, 'w') + "X.com",

         exception_info<DnsProtocol::bad_name>("length too long"s, 1),
         "",
         ""
      },

      {
         TEST_CONTEXT("below 255 limit"),
         std::string(077, 'w') + '.' + std::string(077, 'a') + '.' + std::string(077, 'b') + '.' + std::string(075, 'c'),

         exception_info(),
         std::string(077, 'w') + '.' + std::string(077, 'a') + '.' + std::string(077, 'b') + '.' + std::string(075, 'c'),
         "\77"s + std::string(077, 'w') + "\077"s + std::string(077, 'a') + "\077"s + std::string(077, 'b') + "\075"s + std::string(075, 'c') + "\0"s,
      },

      {
         TEST_CONTEXT("beyond 255 limit (no room for chars)"),
         std::string(077, 'w') + '.' + std::string(077, 'a') + '.' + std::string(077, 'b') + '.' + std::string(070, 'c') + '.' + std::string(06, 'd'),

         exception_info<DnsProtocol::bad_name>("length too long"s, 2),
         "",
         "",
      },

      {
         TEST_CONTEXT("beyond 255 limit (no room for internal \\0)"),
         std::string(077, 'w') + '.' + std::string(077, 'a') + '.' + std::string(077, 'b') + '.' + std::string(075, 'c') + 'X',

         exception_info<DnsProtocol::bad_name>("length too long"s, 3),
         "",
         "",
      },
   };

   /////////////////////////////////////////////////////

   for(auto Datum : TestData)
   {
      BOOST_TEST_CONTEXT(Datum.test_context)
      {
         auto pQN = make_my_unique<DnsProtocol::QualifiedName>(); // TEST OBJECT

         std::string initial_name     = "www.initial.com"s;
         std::string initial_raw_data = "\3www\7initial\3com\0"s;

         BOOST_REQUIRE(initial_name != Datum.expected_name);

         pQN->Set(initial_name);

         if(Datum.expected_exception)
         {
            BOOST_CHECK_EXCEPTION(pQN->Set(Datum.input_name), std::exception, Datum.expected_exception);   // THE TEST

            BOOST_CHECK_EQUAL(pQN->Get(), initial_name);

            BOOST_CHECK_NO_THROW(BOOST_CHECK_EQUAL(static_cast<std::ostringstream&>(std::ostringstream() << *pQN).str(), initial_name));

            BOOST_CHECK_NO_THROW(BOOST_CHECK_EQUAL(OctRep(pQN->Save()), OctRep(initial_raw_data)));
         }
         else
         {
            BOOST_CHECK_NO_THROW(pQN->Set(Datum.input_name));   // THE TEST

            BOOST_CHECK_EQUAL(pQN->Get(), Datum.expected_name);

            BOOST_CHECK_NO_THROW(BOOST_CHECK_EQUAL(static_cast<std::ostringstream&>(std::ostringstream() << *pQN).str(), Datum.expected_name));

            BOOST_CHECK_NO_THROW(BOOST_CHECK_EQUAL(OctRep(pQN->Save()), OctRep(Datum.expected_raw_data)));
         }
      }
   }
}


BOOST_AUTO_TEST_CASE(DnsProtocol_QualifiedName_Load)
{
   // std::cout << getpid() << "\n"; sleep(15);

   struct
   {
      std::string test_context;
      std::string input_raw_data;

      exception_info_t expected_exception;
      std::string expected_name;
      int expected_distance;
   }
   TestData[] =
   {
      {
         TEST_CONTEXT("empty"),
         "\0"s,

         exception_info(),
         "",
         1,
      },

      {
         TEST_CONTEXT("simple case"),
         "\3www\5yahoo\3com\0"s,

         exception_info(),
         "www.yahoo.com",
         15,
      },

      {
         TEST_CONTEXT("consumption not beyond null"),
         "\3www\5yahoo\3com\0ABCDEFGHIJKLMNOPQRSTUVWXYZ"s,

         exception_info(),
         "www.yahoo.com",
         15,
      },

      {
         TEST_CONTEXT("within exactly supported length of 255"),
         "\77"s + std::string(077, 'w') +
         "\77"s + std::string(077, 'a') +
         "\77"s + std::string(077, 'b') +
         "\75"s + std::string(075, 'c') + "\0ABCD"s,

         exception_info(),
         std::string(077, 'w') + '.' +
         std::string(077, 'a') + '.' +
         std::string(077, 'b') + '.' + std::string(075, 'c'),
         255,
      },

      {
         TEST_CONTEXT("bad length in data > 255"),
         "\77"s + std::string(077, 'w') +
         "\77"s + std::string(077, 'a') +
         "\77"s + std::string(077, 'b') +
         "\76"s + std::string(076, 'c') + "\0ABCD"s,

         exception_info<DnsProtocol::bad_data_stream>("length too long"s, 1),
         "",
         255,
      },

      {
         TEST_CONTEXT("bad length in data (first label > 63)"),
         "\100www\5yahoo\3com\0ABCD"s,

         exception_info<DnsProtocol::bad_data_stream>("length too long"s, 2),
         "",
         0,
      },

      {
         TEST_CONTEXT("bad length in data (middle label > 63)"),
         "\3www\100yahoo\3com\0ABCD"s,

         exception_info<DnsProtocol::bad_data_stream>("length too long"s, 2),
         "",
         4,
      },

      {
         TEST_CONTEXT("truncated data from middle of label"),
         "\3www\5ya"s,
         exception_info<DnsProtocol::bad_data_stream>("truncated"s, 2),
         "",
         7,
      },

      {
         TEST_CONTEXT("truncated data (missing null)"),
         "\3www\5yahoo\3com"s,
         exception_info<DnsProtocol::bad_data_stream>("truncated"s, 2),
         "",
         14,
      },

   };

   /////////////////////////////////////////////////////

   for(auto Datum : TestData)
   {
      BOOST_TEST_CONTEXT(Datum.test_context)
      {
         // Check sane test configuration
         auto pQN = make_my_unique<DnsProtocol::QualifiedName>(); // TEST OBJECT

         std::string initial_raw_data = "\3www\7initial\3com\0"s;
         std::string initial_name     = "www.initial.com"s;

         BOOST_REQUIRE(initial_raw_data != Datum.input_raw_data);

         pQN->Set(initial_name); // set the object to some initial state

         if(Datum.expected_exception)
         {
            auto&& b = Datum.input_raw_data.begin();
            auto&& e = Datum.input_raw_data.end();

            BOOST_CHECK_EXCEPTION(pQN->Load(b, e), std::exception, Datum.expected_exception); // THE TEST

            BOOST_CHECK(0 <= std::distance(Datum.input_raw_data.begin(), b) && std::distance(Datum.input_raw_data.begin(), b) <= Datum.expected_distance);

            BOOST_CHECK_NO_THROW(BOOST_CHECK_EQUAL(pQN->Get(), initial_name));

            BOOST_CHECK_NO_THROW(BOOST_CHECK_EQUAL(static_cast<std::ostringstream&>(std::ostringstream() << *pQN).str(), initial_name));

            BOOST_CHECK_NO_THROW(BOOST_CHECK_EQUAL(OctRep(pQN->Save()), OctRep(initial_raw_data)));
         }
         else
         {
            auto&& b = Datum.input_raw_data.begin();
            auto&& e = Datum.input_raw_data.end();

            BOOST_CHECK_NO_THROW(pQN->Load(b, e)); // THE TEST

            BOOST_CHECK_EQUAL(std::distance(Datum.input_raw_data.begin(), b), Datum.expected_distance);

            BOOST_CHECK_NO_THROW(BOOST_CHECK_EQUAL(pQN->Get(), Datum.expected_name));

            BOOST_CHECK_NO_THROW(BOOST_CHECK_EQUAL(static_cast<std::ostringstream&>(std::ostringstream() << *pQN).str(), Datum.expected_name));

            BOOST_CHECK_NO_THROW(BOOST_CHECK_EQUAL(OctRep(pQN->Save()), OctRep(Datum.input_raw_data.substr(0, Datum.expected_distance))));
         }
      }
   }
}


BOOST_AUTO_TEST_CASE(DnsProtocol_Question_Save)
{
   struct
   {
      std::string test_context;

      std::string input_QName;
      uint16_t input_QType;
      uint16_t input_QClass;

      exception_info_t expected_exception;
      std::string expected_raw_data;
      std::string expected_stream;
   }
   TestData[] =
   {
      {
         TEST_CONTEXT("simple case"),
         "www.yahoo.com", 0xA, 0xB,

         exception_info(),
         "\3www\5yahoo\3com\0\0\xA\0\xB"s,
         "{ QName=www.yahoo.com, QType=10, QClass=11 }",
      },
   };

   /////////////////////////////////////////////////////

   for(auto Datum : TestData)
   {
      BOOST_TEST_CONTEXT(Datum.test_context)
      {
         auto pQ = make_my_unique<DnsProtocol::Question>(); // TEST OBJECT

         pQ->QName(Datum.input_QName);
         pQ->QType(Datum.input_QType);
         pQ->QClass(Datum.input_QClass);

         BOOST_CHECK_EQUAL(pQ->QName(), Datum.input_QName);
         BOOST_CHECK_EQUAL(pQ->QType(), Datum.input_QType);
         BOOST_CHECK_EQUAL(pQ->QClass(), Datum.input_QClass);

         BOOST_CHECK_EQUAL(static_cast<std::ostringstream&>(std::ostringstream() << *pQ).str(), Datum.expected_stream);

         BOOST_CHECK_EQUAL(OctRep(pQ->Save()), OctRep(Datum.expected_raw_data));
      }
   }
}


BOOST_AUTO_TEST_CASE(DnsProtocol_Question_Load)
{
   struct
   {
      std::string test_context;

      std::string input_raw_data;

      int expected_distance;
      std::string expected_QName;
      uint16_t expected_QType;
      uint16_t expected_QClass;
      std::string expected_stream;
   }
   TestData[] =
   {
      {
         TEST_CONTEXT("Load simple case (with excess data)"),
         "\3www\5yahoo\3com\0\0\xA\0\xBZABCDEFGHIJ"s,

         19,
         "www.yahoo.com", 0xA, 0xB,

         "{ QName=www.yahoo.com, QType=10, QClass=11 }",
      },
   };

   /////////////////////////////////////////////////////

   for(auto Datum : TestData)
   {
      BOOST_TEST_CONTEXT(Datum.test_context)
      {
         auto pQ = make_my_unique<DnsProtocol::Question>(); // TEST OBJECT

         auto&& b = Datum.input_raw_data.begin();
         auto&& e = Datum.input_raw_data.end();

         BOOST_CHECK_NO_THROW( pQ->Load(b, e) ); // THE TEST

         BOOST_CHECK_EQUAL(pQ->QName(), Datum.expected_QName);
         BOOST_CHECK_EQUAL(pQ->QType(), Datum.expected_QType);
         BOOST_CHECK_EQUAL(pQ->QClass(), Datum.expected_QClass);

         BOOST_CHECK_EQUAL(std::distance(Datum.input_raw_data.begin(), b), Datum.expected_distance);
         BOOST_CHECK_EQUAL(static_cast<std::ostringstream&>(std::ostringstream() << *pQ).str(), Datum.expected_stream);
         BOOST_CHECK_EQUAL(OctRep(pQ->Save()), OctRep(Datum.input_raw_data.substr(0, Datum.expected_distance)));
      }
   }
}
