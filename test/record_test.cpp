#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE record_test
#include <boost/test/unit_test.hpp>

#include "dns/record.h"

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

      std::string input_Name;
      dns::rr_type_t input_Type;
      dns::rr_class_t input_Class;
      uint32_t input_TTL;
      std::string input_Data;

      exception_info_t expected_exception;
      std::string expected_raw_data;
      std::string expected_stream;
   }
   TestData[] =
   {
      {
         TEST_CONTEXT("simple case"),
         "www.yahoo.com", dns::rr_type_t::rec_mx, dns::rr_class_t::internet, 131073u, "_recdata_",

         exception_info(),
         "\3www\5yahoo\3com\0\0\xF\0\x1\0\x2\0\x1\0\x9_recdata_"s,
         "{ Name=www.yahoo.com, Type=mx, Class=internet, TTL=131073 }",
      },
   };

   /////////////////////////////////////////////////////

   for(auto Datum : TestData)
   {
      BOOST_TEST_CONTEXT(Datum.test_context)
      {
         auto pR = make_my_unique<dns::record_t>(); // TEST OBJECT

         pR->Name(Datum.input_Name);
         pR->Type(Datum.input_Type);
         pR->Class(Datum.input_Class);
         pR->TTL(Datum.input_TTL);
         pR->Data(Datum.input_Data);

         BOOST_CHECK_EQUAL(pR->Name(), Datum.input_Name);
         BOOST_CHECK_EQUAL(pR->Type(), Datum.input_Type);
         BOOST_CHECK_EQUAL(pR->Class(), Datum.input_Class);
         BOOST_CHECK_EQUAL(pR->TTL(), Datum.input_TTL);
         BOOST_CHECK_EQUAL(pR->Data(), Datum.input_Data);
         BOOST_CHECK_EQUAL(pR->DataLength(), Datum.input_Data.size());

         BOOST_CHECK_EQUAL(static_cast<std::ostringstream&>(std::ostringstream() << *pR).str(), Datum.expected_stream);

         {
            auto&& tr = dns::name_offset_tracker_t{};

            BOOST_CHECK_NO_THROW(dns::save_to(tr, *pR));

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

      std::string input_raw_data;

      int expected_distance;
      std::string expected_Name;
      dns::rr_type_t expected_Type;
      dns::rr_class_t expected_Class;
      uint32_t expected_TTL;
      std::string expected_Data;
      std::string expected_stream;
   }
   TestData[] =
   {
      {
         TEST_CONTEXT("Load simple case (with excess data)"),
         "\3www\5yahoo\3com\0\0\xF\0\x1\0\x2\0\x1\0\x9_recdata_ABCDEFGHIJ"s,

         34, "www.yahoo.com", dns::rr_type_t::rec_mx, dns::rr_class_t::internet, 131073u, "_recdata_",
         "{ Name=www.yahoo.com, Type=mx, Class=internet, TTL=131073 }",
      },
   };

   /////////////////////////////////////////////////////

   for(auto Datum : TestData)
   {
      BOOST_TEST_CONTEXT(Datum.test_context)
      {
         auto pR = make_my_unique<dns::record_t>(); // TEST OBJECT

         auto&& b = Datum.input_raw_data.begin();
         auto&& e = Datum.input_raw_data.end();
         auto&& tr = dns::name_offset_tracker_t{};

         BOOST_CHECK_NO_THROW(dns::load_from(tr, b, e, *pR));   // THE TEST

         BOOST_CHECK_EQUAL(pR->Name(), Datum.expected_Name);
         BOOST_CHECK_EQUAL(pR->Type(), Datum.expected_Type);
         BOOST_CHECK_EQUAL(pR->Class(), Datum.expected_Class);
         BOOST_CHECK_EQUAL(pR->TTL(), Datum.expected_TTL);
         BOOST_CHECK_EQUAL(pR->Data(), Datum.expected_Data);
         BOOST_CHECK_EQUAL(pR->DataLength(), Datum.expected_Data.size());

         BOOST_CHECK_EQUAL(std::distance(Datum.input_raw_data.begin(), b), Datum.expected_distance);
         BOOST_CHECK_EQUAL(static_cast<std::ostringstream&>(std::ostringstream() << *pR).str(), Datum.expected_stream);
      }
   }
}
