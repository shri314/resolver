#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE label_list_test
#include <boost/test/unit_test.hpp>

#include "dns/label_list.h"

#include "test/exception_info.h"
#include "test/make_my_unique.h"
#include "test/test_context.h"
#include "util/oct_dump.h"

#include <boost/algorithm/string.hpp>

#include <string>
#include <sstream>

using namespace std::string_literals;

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
         if(boost::algorithm::contains(Datum.test_context, "GDB:"))
            BOOST_TEST_MESSAGE(getpid()), sleep(30);

         dns::name_offset_tracker_t tr{Datum.input_prefill_offset};

         {
            auto&& input = Datum.input_prefill_name;

            if(!input.empty())
            {
               auto pLL = make_my_unique<dns::label_list_t>();    // TEST OBJECT

               BOOST_CHECK_NO_THROW(pLL->Name(input)); // THE TEST

               BOOST_CHECK_EQUAL(pLL->Name(), input);

               BOOST_CHECK_EQUAL(static_cast<std::ostringstream&>(std::ostringstream() << *pLL).str(), "[" + input + "]");

               BOOST_CHECK_NO_THROW(dns::save_to(tr, *pLL));   // THE TEST (PART 1)
            }
         }

         {
            auto&& input = Datum.input_name;

            auto pLL = make_my_unique<dns::label_list_t>();    // NEW TEST OBJECT

            BOOST_CHECK_NO_THROW(pLL->Name(input)); // NEW THE TEST

            BOOST_CHECK_EQUAL(pLL->Name(), input);

            BOOST_CHECK_EQUAL(static_cast<std::ostringstream&>(std::ostringstream() << *pLL).str(), "[" + input + "]");

            if(Datum.expected_exception)
            {
               BOOST_CHECK_EXCEPTION(dns::save_to(tr, *pLL), std::exception, Datum.expected_exception);   // THE TEST (PART 2)
            }
            else
            {
               BOOST_CHECK_NO_THROW(dns::save_to(tr, *pLL));   // THE TEST (PART 2)
            }

            BOOST_CHECK_EQUAL(util::oct_dump(tr.store()), util::oct_dump(Datum.expected_raw_data));
         }
      }
   }
}

BOOST_AUTO_TEST_CASE(dns_load_from)
{
   struct
   {
      std::string test_context;
      uint16_t input_initial_offset;
      std::string input_raw_data;

      struct expectation_info
      {
         exception_info_t exception;
         std::string name;
         int distance;
      };

      std::vector<expectation_info> expected;
   }
   TestData[] =
   {
      {
         TEST_CONTEXT("empty"),
         1, "\0"s,

         {
            { exception_info(), "", 1,},
         },
      },

      {
         TEST_CONTEXT("simple case"),
         15, "\3www\5yahoo\3com\0"s,

         {
            { exception_info(), "www.yahoo.com", 15, },
         },
      },

      {
         TEST_CONTEXT("a ptr_offset with no previous occurrence"),
         45, "\300\55"s,

         {
            { exception_info<dns::exception::bad_data_stream>("unseen offset"s, 1), "", 2, },
         },
      },

      {
         TEST_CONTEXT("repeating domains (valid ptr_offset)"),
         45, "\3www\5yahoo\3com\0\300\55"s,

         {
            { exception_info(), "www.yahoo.com", 15, },
            { exception_info(), "www.yahoo.com", 17, },
         },
      },

      {
         TEST_CONTEXT("repeating subdomains (valid ptr_offsets)"),
         45, "\3www\5yahoo\3com\0\3www\5gmail\300\67\300\74"s,

         {
            { exception_info(), "www.yahoo.com", 15, },
            { exception_info(), "www.gmail.com", 27, },
            { exception_info(), "www.gmail.com", 29, },
         },
      },

      {
         TEST_CONTEXT("repeating same domains (with multiple ptr_offset)"),
         45, "\3www\5yahoo\3com\0\3www\5yahoo\3com\0\300\55\300\74"s,

         {
            { exception_info(), "www.yahoo.com", 15, },
            { exception_info(), "www.yahoo.com", 30, },
            { exception_info(), "www.yahoo.com", 32, },
            { exception_info(), "www.yahoo.com", 34, },
         },
      },

      {
         TEST_CONTEXT("bad length in data (first label > 63)"),
         0, "\100www\5yahoo\3com\0ABCD"s,

         {
            { exception_info<dns::exception::bad_data_stream>("length too long"s, 2), "", 1, },
         },
      },

      {
         TEST_CONTEXT("bad length in data (middle label > 63)"),
         0, "\3www\100yahoo\3com\0ABCD"s,

         {
            { exception_info<dns::exception::bad_data_stream>("length too long"s, 2), "", 5, },
         },
      },

      {
         TEST_CONTEXT("truncated data from middle of label"),
         0, "\3www\5ya"s,
         {
            { exception_info<dns::exception::bad_data_stream>("truncated"s, 2), "", 7, },
         },
      },

      {
         TEST_CONTEXT("truncated data (missing null)"),
         0, "\3www\5yahoo\3com"s,

         {
            { exception_info<dns::exception::bad_data_stream>("truncated"s, 2), "", 14, },
         },
      },

      {
         TEST_CONTEXT("truncated data (missing second byte of ptr_offset)"),
         0, "\3www\5yahoo\3com\301"s,

         {
            { exception_info<dns::exception::bad_data_stream>("truncated"s, 2), "", 15, },
         },
      },
   };

   /////////////////////////////////////////////////////

   for(auto Datum : TestData)
   {
      BOOST_TEST_CONTEXT(Datum.test_context)
      {
         if(boost::algorithm::contains(Datum.test_context, "GDB:"))
            BOOST_TEST_MESSAGE(getpid()), sleep(30);

         // Check sane test configuration
         auto pLL = make_my_unique<dns::label_list_t>(); // TEST OBJECT

         auto&& b = Datum.input_raw_data.begin();
         auto&& e = Datum.input_raw_data.end();
         auto&& tr = dns::name_offset_tracker_t{Datum.input_initial_offset};

         for(auto && expected : Datum.expected)
         {
            if(expected.exception)
            {
               BOOST_CHECK_EXCEPTION(dns::load_from(tr, b, e, *pLL), std::exception, expected.exception); // THE TEST

               BOOST_CHECK(0 <= std::distance(Datum.input_raw_data.begin(), b) && std::distance(Datum.input_raw_data.begin(), b) <= expected.distance);

               break;
            }
            else
            {
               BOOST_CHECK_NO_THROW(dns::load_from(tr, b, e, *pLL)); // THE TEST

               BOOST_CHECK_EQUAL(std::distance(Datum.input_raw_data.begin(), b), expected.distance);

               BOOST_CHECK_NO_THROW(BOOST_CHECK_EQUAL(pLL->Name(), expected.name));

               BOOST_CHECK_NO_THROW(BOOST_CHECK_EQUAL(static_cast<std::ostringstream&>(std::ostringstream() << *pLL).str(), "[" + expected.name + "]"));
            }
         }
      }
   }
}
