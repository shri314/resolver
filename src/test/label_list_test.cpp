#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE label_list_test
#include <boost/test/unit_test.hpp>

#include "dns/label_list.h"

#include "test_context.h"
#include "raw_dump.h"

#include <boost/algorithm/string.hpp>

#include <string>
#include <sstream>
#include <iostream>

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

         if(auto f = dynamic_cast<const dns::exception::bad_name*>(&e))
         {
            BOOST_CHECK_EQUAL(f->code(), code);
            return true;
         }

         if(auto f = dynamic_cast<const dns::exception::bad_data_stream*>(&e))
         {
            BOOST_CHECK_EQUAL(f->code(), code);
            return true;
         }

         if(auto f = dynamic_cast<const dns::exception::bad_ptr_offset*>(&e))
         {
            BOOST_CHECK_EQUAL(f->code(), code);
            return true;
         }

         BOOST_TEST(false, "unexpected exception");
         return false;
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


BOOST_AUTO_TEST_CASE(dns_save_to)
{
   struct
   {
      std::string test_context;
      uint16_t input_prefill_offset;
      std::string input_prefill_name;
      std::string input_name;

      exception_info_t expected_exception;
      std::string expected_raw_data;
   }
   TestData[] =
   {
      {
         TEST_CONTEXT("empty"),
         0,
         "",
         "",

         exception_info(),
         "\0"s,
      },

      {
         TEST_CONTEXT("empty domain if they reoccur are not tracked and replaced by ptr_offset"),
         45,
         "",
         "",

         exception_info(),
         "\0"s,
      },

      {
         TEST_CONTEXT("simple domain case"),
         0,
         "",
         "www.yahoo.com",

         exception_info(),
         "\3www\5yahoo\3com\0"s,
      },

      {
         TEST_CONTEXT("just data case - no dots"),
         0,
         "",
         "wwwyahoocom",

         exception_info(),
         "\13wwwyahoocom\0"s,
      },

      {
         TEST_CONTEXT("with single ending dot (absolute domain)"),
         0,
         "",
         "www.yahoo.com.",

         exception_info(),
         "\3www\5yahoo\3com\0"s,
      },

      {
         TEST_CONTEXT("repeating domains should be replaced by ptr_offset"),
         45,
         "www.yahoo.com",
         "www.yahoo.com",

         exception_info(),
         "\3www\5yahoo\3com\0\300\55"s,
      },

      {
         TEST_CONTEXT("repeating domains (both domains with single ending dot) (ptr_offset)"),
         45,
         "www.yahoo.com.",
         "www.yahoo.com.",

         exception_info(),
         "\3www\5yahoo\3com\0\300\55"s,
      },

      {
         TEST_CONTEXT("repeating domains (second domain with single ending dot) (ptr_offset)"),
         45,
         "www.yahoo.com",
         "www.yahoo.com.",

         exception_info(),
         "\3www\5yahoo\3com\0\300\55"s,
      },

      {
         TEST_CONTEXT("repeating domains (first domain with single ending dot) (ptr_offset)"),
         45,
         "www.yahoo.com.",
         "www.yahoo.com",

         exception_info(),
         "\3www\5yahoo\3com\0\300\55"s,
      },

      {
         TEST_CONTEXT("repeating subdomain case (level1) (subdomain replaced by ptr_offset)"),
         45,
         "www.google.com",
         "www.yahoo.com",

         exception_info(),
         "\3www\6google\3com\0\3www\5yahoo\300\70"s,
      },

      {
         TEST_CONTEXT("repeating subdomain case (level2) (subdomain replaced by ptr_offset)"),
         45,
         "mx1.yahoo.com",
         "www.yahoo.com",

         exception_info(),
         "\3mx1\5yahoo\3com\0\3www\300\61"s,
      },

      {
         TEST_CONTEXT("bad ptr_offset"),
         16384,
         "www.yahoo.com",
         "www.yahoo.com",

         exception_info<dns::exception::bad_ptr_offset>("offset too long"s, 1),
         "\3www\5yahoo\3com\0"s,
      },

      {
         TEST_CONTEXT("with extra ending dots - they are ignored"),
         0,
         "",
         "www.yahoo.com....",

         exception_info(),
         "\3www\5yahoo\3com\0"s,
      },

      {
         TEST_CONTEXT("with extra dots in the middle"),
         0,
         "",
         "www.yahoo..com",

         exception_info<dns::exception::bad_name>("wrong format"s, 1),
         "\3www\5yahoo"s,
      },

      {
         TEST_CONTEXT("below 63 label limit"),
         0,
         "",
         std::string(63, 'w') + ".com",

         exception_info(),
         "\77"s + std::string(63, 'w') + "\3com\0"s,
      },

      {
         TEST_CONTEXT("below 63 label limit + ptr_offset"),
         45,
         std::string(63, 'w') + ".com",
         std::string(63, 'w') + ".com",

         exception_info(),
         "\77"s + std::string(63, 'w') + "\3com\0\300\55"s,
      },

      {
         TEST_CONTEXT("beyond 63 label limit"),
         0,
         "",
         std::string(63, 'w') + "X.com",

         exception_info<dns::exception::bad_name>("length too long"s, 1),
         "",
      },

      {
         TEST_CONTEXT("a domain way above RFC limit of 255 is supported too"),
         0,
         "",
         std::string(077, 'w') + '.' + std::string(077, 'w') + '.' + std::string(077, 'a') + '.' + std::string(077, 'b') + '.' + std::string(075, 'c'),

         exception_info(),
         "\77"s + std::string(077, 'w') + "\77"s + std::string(077, 'w') + "\077"s + std::string(077, 'a') + "\077"s + std::string(077, 'b') + "\075"s + std::string(075, 'c') + "\0"s,
      },
   };

   /////////////////////////////////////////////////////

   for(auto Datum : TestData)
   {
      BOOST_TEST_CONTEXT(Datum.test_context)
      {
         if( boost::algorithm::contains(Datum.test_context, "GDB:") )
            BOOST_TEST_MESSAGE( getpid() ), sleep(30);

         std::string store;

         auto&& o = std::back_inserter(store);

         dns::name_offset_tracker_t tr{Datum.input_prefill_offset};

         {
            auto&& input = Datum.input_prefill_name;

            if(!input.empty())
            {
               auto pQN = make_my_unique<dns::label_list_t>();    // TEST OBJECT

               BOOST_CHECK_NO_THROW(pQN->Name(input)); // THE TEST

               BOOST_CHECK_EQUAL(pQN->Name(), input);

               BOOST_CHECK_EQUAL(static_cast<std::ostringstream&>(std::ostringstream() << *pQN).str(), "[" + input + "]");

               BOOST_CHECK_NO_THROW(dns::save_to(o, tr, *pQN));   // THE TEST (PART 1)
            }
         }

         {
            auto&& input = Datum.input_name;

            auto pQN = make_my_unique<dns::label_list_t>();    // NEW TEST OBJECT

            BOOST_CHECK_NO_THROW(pQN->Name(input)); // NEW THE TEST

            BOOST_CHECK_EQUAL(pQN->Name(), input);

            BOOST_CHECK_EQUAL(static_cast<std::ostringstream&>(std::ostringstream() << *pQN).str(), "[" + input + "]");

            if(Datum.expected_exception)
            {
               BOOST_CHECK_EXCEPTION(dns::save_to(o, tr, *pQN), std::exception, Datum.expected_exception);   // THE TEST (PART 2)
            }
            else
            {
               BOOST_CHECK_NO_THROW(dns::save_to(o, tr, *pQN));   // THE TEST (PART 2)
            }

            BOOST_CHECK_EQUAL(OctRep(store), OctRep(Datum.expected_raw_data));
         }
      }
   }
}


BOOST_AUTO_TEST_CASE(dns_load_from)
{
}
