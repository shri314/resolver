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

      BOOST_CHECK_EQUAL(OctRep(wd), OctRep(req));
   }

   // Load
   {
      std::string res =
         "\xf9\xac\x81\x80\x00\x01\x00\x03\x00\x00\x00\x00\5yahoo\3com\0\0\17\0\1\300\f\0\17\0\1\0\0\4\245\0\31\0\1\4mta7\3am0\10yahoodns\3net\0\300\f\0\17\0\1\0\0\4\245\0\t\0\1\4mta6\300.\300\f\0\17\0\1\0\0\4\245\0\t\0\1\4mta5\300."s;
      auto&& begin = res.cbegin();

      auto p = make_my_unique<DnsProtocol::Header>();

      p->Load(begin, res.cend());

      BOOST_CHECK_EQUAL(std::distance(res.cbegin(), begin), 12);

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
         p->Load(begin, res.cend()),
         DnsProtocol::bad_data_stream,
         [](const auto & e)
      {
         BOOST_CHECK_EQUAL(e.what(), "truncated"s);
         BOOST_CHECK_EQUAL(e.code(), 1);
         return true;
      }
      );
   }
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


BOOST_AUTO_TEST_CASE(DnsProtocol_QualifiedName_Save)
{
   struct
   {
      std::string test_context;
      std::string name_to_set;

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
         auto qn = make_my_unique<DnsProtocol::QualifiedName>(); // TEST OBJECT

         std::string initial_name     = "www.initial.com"s;
         std::string initial_raw_data = "\3www\7initial\3com\0"s;

         BOOST_REQUIRE(initial_name != Datum.expected_name);

         qn->Set(initial_name);

         if(Datum.expected_exception)
         {
            BOOST_CHECK_EXCEPTION(qn->Set(Datum.name_to_set), std::exception, Datum.expected_exception);   // THE TEST

            BOOST_CHECK_EQUAL(qn->Get(), initial_name);

            BOOST_CHECK_NO_THROW(BOOST_CHECK_EQUAL(static_cast<std::ostringstream&>(std::ostringstream() << *qn).str(), initial_name));

            BOOST_CHECK_NO_THROW(BOOST_CHECK_EQUAL(OctRep(qn->Save()), OctRep(initial_raw_data)));
         }
         else
         {
            BOOST_CHECK_NO_THROW(qn->Set(Datum.name_to_set));   // THE TEST

            BOOST_CHECK_EQUAL(qn->Get(), Datum.expected_name);

            BOOST_CHECK_NO_THROW(BOOST_CHECK_EQUAL(static_cast<std::ostringstream&>(std::ostringstream() << *qn).str(), Datum.expected_name));

            BOOST_CHECK_NO_THROW(BOOST_CHECK_EQUAL(OctRep(qn->Save()), OctRep(Datum.expected_raw_data)));
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
      std::string raw_data;

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
         TEST_CONTEXT("consumption not beyond further data"),
         "\3www\5yahoo\3com\0ABCDEFGHIJKLMNOPQRSTUVWXYZ"s,

         exception_info(),
         "www.yahoo.com",
         15,
      },

      {
         TEST_CONTEXT("Load within exactly supported length of 255"),
         "\77"s + std::string(077, 'w') +
         "\77"s + std::string(077, 'a') +
         "\77"s + std::string(077, 'b') +
         "\75"s + std::string(075, 'c') + "\0"s,

         exception_info(),
         std::string(077, 'w') + '.' +
         std::string(077, 'a') + '.' +
         std::string(077, 'b') + '.' + std::string(075, 'c'),
         255,
      },

   };

   ///////////////////////////////////////////////////

   // - FIXME - STOPPED HERE
   int* x = 10;
  
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
         [](const auto & e)
      {
         BOOST_CHECK_EQUAL(e.what(), "length too long"s);
         BOOST_CHECK_EQUAL(e.code(), 1);
         return true;
      }
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
         [](const auto & e)
      {
         BOOST_CHECK_EQUAL(e.what(), "length too long"s);
         BOOST_CHECK_EQUAL(e.code(), 2);
         return true;
      }
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
         [](const auto & e)
      {
         BOOST_CHECK_EQUAL(e.what(), "length too long"s);
         BOOST_CHECK_EQUAL(e.code(), 2);
         return true;
      }
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
         [](const auto & e)
      {
         BOOST_CHECK_EQUAL(e.what(), "truncated"s);
         BOOST_CHECK_EQUAL(e.code(), 3);
         return true;
      }
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
         [](const auto & e)
      {
         BOOST_CHECK_EQUAL(e.what(), "truncated"s);
         BOOST_CHECK_EQUAL(e.code(), 2);
         return true;
      }
      );

      BOOST_CHECK_EQUAL(qn.Get(), "www.initial.com");
   }


   /////////////////////////////////////////////////////

   for(auto Datum : TestData)
   {
      BOOST_TEST_CONTEXT(Datum.test_context)
      {
         // Check sane test configuration
         auto qn = make_my_unique<DnsProtocol::QualifiedName>(); // TEST OBJECT

         std::string initial_raw_data = "\3www\7initial\3com\0"s;
         std::string initial_name     = "www.initial.com"s;

         BOOST_REQUIRE(initial_raw_data != Datum.raw_data);

         qn->Set(initial_name); // set the object to some initial state

         if(Datum.expected_exception)
         {
            auto&& b = Datum.raw_data.begin();
            auto&& e = Datum.raw_data.end();

            BOOST_CHECK_EXCEPTION(qn->Load(b, e), std::exception, Datum.expected_exception); // THE TEST

            BOOST_CHECK( 0 <= std::distance(b, e) && std::distance(b, e) <= Datum.expected_distance );

            BOOST_CHECK_NO_THROW(BOOST_CHECK_EQUAL(qn->Get(), initial_name));

            BOOST_CHECK_NO_THROW(BOOST_CHECK_EQUAL(static_cast<std::ostringstream&>(std::ostringstream() << *qn).str(), initial_name));

            BOOST_CHECK_NO_THROW(BOOST_CHECK_EQUAL(OctRep(qn->Save()), OctRep(initial_raw_data)));
         }
         else
         {
            auto&& b = Datum.raw_data.begin();
            auto&& e = Datum.raw_data.end();

            BOOST_CHECK_NO_THROW(qn->Load(b, e)); // THE TEST

            BOOST_CHECK_EQUAL(std::distance(Datum.raw_data.begin(), b), Datum.expected_distance);

            BOOST_CHECK_NO_THROW(BOOST_CHECK_EQUAL(qn->Get(), Datum.expected_name));

            BOOST_CHECK_NO_THROW(BOOST_CHECK_EQUAL(static_cast<std::ostringstream&>(std::ostringstream() << *qn).str(), Datum.expected_name));

            BOOST_CHECK_NO_THROW(BOOST_CHECK_EQUAL(OctRep(qn->Save()), OctRep(Datum.raw_data.substr(0, Datum.expected_distance))));
         }
      }
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

      BOOST_CHECK_EQUAL(OctRep(wd), OctRep(req));
   }

   // Load
   {
      std::string res = "\5yahoo\3com\x00\x00\x0f\x00\x01"s;
      auto&& begin = res.cbegin();

      auto p = make_my_unique<DnsProtocol::Question>();

      p->Load(begin, res.cend());

      BOOST_CHECK_EQUAL(p->QName(), "yahoo.com");
      BOOST_CHECK_EQUAL(p->QType(), 15);
      BOOST_CHECK_EQUAL(p->QClass(), 1);
   }
}
