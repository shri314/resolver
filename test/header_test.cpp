#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE header_test
#include <boost/test/unit_test.hpp>

#include "dns/header.h"

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

      uint16_t input_ID;

      bool input_QR_Flag;
      bool input_AA_Flag;
      bool input_TC_Flag;
      bool input_RD_Flag;
      bool input_RA_Flag;
      bool input_AD_Flag;
      bool input_CD_Flag;

      dns::op_code_t input_OpCode;
      dns::r_code_t input_RCode;

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
         /* QR_Flag */ false, /* AA_Flag */ false, /* TC_Flag */ false, /* RD_Flag */ false, /* RA_Flag */ false, /* AD_Flag */ false, /* CD_Flag */ false,
         /* OpCode */ dns::op_code_t::query, /* RCode */ dns::r_code_t::no_error,
         /* QdCount */ 1, /* AnCount */ 0, /* NsCount */ 0, /* ArCount */ 0,

         "\xf9\xac\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"s,
         "{ ID=63916, Flags=[], OpCode=query, RCode=no_error, QdCount=1, AnCount=0, NsCount=0, ArCount=0 }",
      },

      {
         TEST_CONTEXT("response header"),

         /* ID */ 0x5006,
         /* QR_Flag */ true, /* AA_Flag */ false, /* TC_Flag */ false, /* RD_Flag */ false, /* RA_Flag */ false, /* AD_Flag */ false, /* CD_Flag */ false,
         /* OpCode */ dns::op_code_t::query, /* RCode */ dns::r_code_t::no_error,
         /* QdCount */ 0, /* AnCount */ 1, /* NsCount */ 0, /* ArCount */ 0,

         "\x50\x06\x80\x00\x00\x00\x00\x01\x00\x00\x00\x00"s,
         "{ ID=20486, Flags=[QR], OpCode=query, RCode=no_error, QdCount=0, AnCount=1, NsCount=0, ArCount=0 }",
      },

      {
         TEST_CONTEXT("response header with RCode"),

         /* ID */ 0x5006,
         /* QR_Flag */ true, /* AA_Flag */ false, /* TC_Flag */ false, /* RD_Flag */ false, /* RA_Flag */ false, /* AD_Flag */ false, /* CD_Flag */ false,
         /* OpCode */ dns::op_code_t::query, /* RCode */ dns::r_code_t::not_auth,
         /* QdCount */ 0, /* AnCount */ 1, /* NsCount */ 0, /* ArCount */ 0,

         "\x50\x06\x80\x09\x00\x00\x00\x01\x00\x00\x00\x00"s,
         "{ ID=20486, Flags=[QR], OpCode=query, RCode=not_auth, QdCount=0, AnCount=1, NsCount=0, ArCount=0 }",
      },

      {
         TEST_CONTEXT("query header with RD"),

         /* ID */ 0xf9ac,
         /* QR_Flag */ false, /* AA_Flag */ false, /* TC_Flag */ false, /* RD_Flag */ true, /* RA_Flag */ false, /* AD_Flag */ false, /* CD_Flag */ false,
         /* OpCode */ dns::op_code_t::query, /* RCode */ dns::r_code_t::no_error,
         /* QdCount */ 1, /* AnCount */ 0, /* NsCount */ 0, /* ArCount */ 0,

         "\xf9\xac\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"s,
         "{ ID=63916, Flags=[RD], OpCode=query, RCode=no_error, QdCount=1, AnCount=0, NsCount=0, ArCount=0 }",
      },

      {
         TEST_CONTEXT("query header with OpCode"),

         /* ID */ 0xf9ac,
         /* QR_Flag */ false, /* AA_Flag */ false, /* TC_Flag */ false, /* RD_Flag */ false, /* RA_Flag */ false, /* AD_Flag */ false, /* CD_Flag */ false,
         /* OpCode */ dns::op_code_t::status, /* RCode */ dns::r_code_t::no_error,
         /* QdCount */ 1, /* AnCount */ 0, /* NsCount */ 0, /* ArCount */ 0,

         "\xf9\xac\x10\x00\x00\x01\x00\x00\x00\x00\x00\x00"s,
         "{ ID=63916, Flags=[], OpCode=status, RCode=no_error, QdCount=1, AnCount=0, NsCount=0, ArCount=0 }",
      },

      {
         TEST_CONTEXT("response header with AA"),

         /* ID */ 0x1111,
         /* QR_Flag */ true, /* AA_Flag */ true, /* TC_Flag */ false, /* RD_Flag */ false, /* RA_Flag */ false, /* AD_Flag */ false, /* CD_Flag */ false,
         /* OpCode */ dns::op_code_t::query, /* RCode */ dns::r_code_t::no_error,
         /* QdCount */ 0, /* AnCount */ 0, /* NsCount */ 1, /* ArCount */ 0,

         "\x11\x11\x84\x00\x00\x00\x00\x00\x00\x01\x00\x00"s,
         "{ ID=4369, Flags=[QR,AA], OpCode=query, RCode=no_error, QdCount=0, AnCount=0, NsCount=1, ArCount=0 }",
      },

      {
         TEST_CONTEXT("response header with TC"),

         /* ID */ 0xFFFF,
         /* QR_Flag */ true, /* AA_Flag */ false, /* TC_Flag */ true, /* RD_Flag */ false, /* RA_Flag */ false, /* AD_Flag */ false, /* CD_Flag */ false,
         /* OpCode */ dns::op_code_t::query, /* RCode */ dns::r_code_t::no_error,
         /* QdCount */ 0, /* AnCount */ 0, /* NsCount */ 0, /* ArCount */ 1,

         "\xFF\xFF\x82\x00\x00\x00\x00\x00\x00\x00\x00\x01"s,
         "{ ID=65535, Flags=[QR,TC], OpCode=query, RCode=no_error, QdCount=0, AnCount=0, NsCount=0, ArCount=1 }",
      },

      {
         TEST_CONTEXT("response header with RA"),

         /* ID */ 0xFFFF,
         /* QR_Flag */ true, /* AA_Flag */ false, /* TC_Flag */ false, /* RD_Flag */ false, /* RA_Flag */ true, /* AD_Flag */ false, /* CD_Flag */ false,
         /* OpCode */ dns::op_code_t::query, /* RCode */ dns::r_code_t::no_error,
         /* QdCount */ 0, /* AnCount */ 0, /* NsCount */ 0, /* ArCount */ 1,

         "\xFF\xFF\x80\x80\x00\x00\x00\x00\x00\x00\x00\x01"s,
         "{ ID=65535, Flags=[QR,RA], OpCode=query, RCode=no_error, QdCount=0, AnCount=0, NsCount=0, ArCount=1 }",
      },

      {
         TEST_CONTEXT("response header with AD"),

         /* ID */ 0xFFFF,
         /* QR_Flag */ true, /* AA_Flag */ false, /* TC_Flag */ false, /* RD_Flag */ false, /* RA_Flag */ false, /* AD_Flag */ true, /* CD_Flag */ false,
         /* OpCode */ dns::op_code_t::query, /* RCode */ dns::r_code_t::no_error,
         /* QdCount */ 0, /* AnCount */ 0, /* NsCount */ 0, /* ArCount */ 1,

         "\xFF\xFF\x80\x20\x00\x00\x00\x00\x00\x00\x00\x01"s,
         "{ ID=65535, Flags=[QR,AD], OpCode=query, RCode=no_error, QdCount=0, AnCount=0, NsCount=0, ArCount=1 }",
      },

      {
         TEST_CONTEXT("response header with CD"),

         /* ID */ 0xFFFF,
         /* QR_Flag */ true, /* AA_Flag */ false, /* TC_Flag */ false, /* RD_Flag */ false, /* RA_Flag */ false, /* AD_Flag */ false, /* CD_Flag */ true,
         /* OpCode */ dns::op_code_t::query, /* RCode */ dns::r_code_t::no_error,
         /* QdCount */ 0, /* AnCount */ 0, /* NsCount */ 0, /* ArCount */ 1,

         "\xFF\xFF\x80\x10\x00\x00\x00\x00\x00\x00\x00\x01"s,
         "{ ID=65535, Flags=[QR,CD], OpCode=query, RCode=no_error, QdCount=0, AnCount=0, NsCount=0, ArCount=1 }",
      },
   };

   /////////////////////////////////////////////////////

   for(auto Datum : TestData)
   {
      BOOST_TEST_CONTEXT(Datum.test_context)
      {
         auto pH = make_my_unique<dns::header_t>(); // TEST OBJECT

         /// Set
         {
            pH->ID(Datum.input_ID);
            pH->QR_Flag(Datum.input_QR_Flag);
            pH->AA_Flag(Datum.input_AA_Flag);
            pH->TC_Flag(Datum.input_TC_Flag);
            pH->RD_Flag(Datum.input_RD_Flag);
            pH->RA_Flag(Datum.input_RA_Flag);
            pH->AD_Flag(Datum.input_AD_Flag);
            pH->CD_Flag(Datum.input_CD_Flag);

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
            BOOST_CHECK_EQUAL(pH->AD_Flag(), Datum.input_AD_Flag);
            BOOST_CHECK_EQUAL(pH->CD_Flag(), Datum.input_CD_Flag);

            BOOST_CHECK_EQUAL(pH->OpCode(),  Datum.input_OpCode);
            BOOST_CHECK_EQUAL(pH->RCode(),   Datum.input_RCode);
            BOOST_CHECK_EQUAL(pH->Res1_Flag(),   0);

            BOOST_CHECK_EQUAL(pH->QdCount(), Datum.input_QdCount);
            BOOST_CHECK_EQUAL(pH->AnCount(), Datum.input_AnCount);
            BOOST_CHECK_EQUAL(pH->NsCount(), Datum.input_NsCount);
            BOOST_CHECK_EQUAL(pH->ArCount(), Datum.input_ArCount);
         }

         {
            std::vector<uint8_t> store;

            {
               auto&& o = std::back_inserter(store);

               dns::name_offset_tracker_t tr;

               BOOST_CHECK_NO_THROW(save_to(tr, o, *pH));   // TEST
            }

            BOOST_CHECK_EQUAL(util::oct_dump(store), util::oct_dump(Datum.expected_raw_data));

            BOOST_CHECK_NO_THROW(BOOST_CHECK_EQUAL(static_cast<std::ostringstream&>(std::ostringstream() << *pH).str(), Datum.expected_stream));
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

      exception_info_t expected_exception;

      int expected_distance;

      std::string expected_stream;

      uint16_t expected_ID;

      bool expected_QR_Flag;
      bool expected_AA_Flag;
      bool expected_TC_Flag;
      bool expected_RD_Flag;
      bool expected_RA_Flag;
      bool expected_AD_Flag;
      bool expected_CD_Flag;

      dns::op_code_t expected_OpCode;
      dns::r_code_t expected_RCode;

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
         "{ ID=63916, Flags=[], OpCode=query, RCode=no_error, QdCount=1, AnCount=0, NsCount=0, ArCount=0 }",

         /* ID */ 0xf9ac,
         /* QR_Flag */ false, /* AA_Flag */ false, /* TC_Flag */ false, /* RD_Flag */ false, /* RA_Flag */ false, /* AD_Flag */ false, /* CD_Flag */ false,
         /* OpCode */ dns::op_code_t::query, /* RCode */ dns::r_code_t::no_error,
         /* QdCount */ 1, /* AnCount */ 0, /* NsCount */ 0, /* ArCount */ 0,
      },

      {
         TEST_CONTEXT("Load query header (with data beyond header)"),
         "\xf9\xac\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00ZABCDEFGHIJKLMNOP"s,

         exception_info(),
         12,
         "{ ID=63916, Flags=[], OpCode=query, RCode=no_error, QdCount=1, AnCount=0, NsCount=0, ArCount=0 }",

         /* ID */ 0xf9ac,
         /* QR_Flag */ false, /* AA_Flag */ false, /* TC_Flag */ false, /* RD_Flag */ false, /* RA_Flag */ false, /* AD_Flag */ false, /* CD_Flag */ false,
         /* OpCode */ dns::op_code_t::query, /* RCode */ dns::r_code_t::no_error,
         /* QdCount */ 1, /* AnCount */ 0, /* NsCount */ 0, /* ArCount */ 0,
      },

      {
         TEST_CONTEXT("Load response header"),
         "\x50\x06\x80\x00\x00\x00\x00\x01\x00\x00\x00\x00"s,

         exception_info(),
         12,
         "{ ID=20486, Flags=[QR], OpCode=query, RCode=no_error, QdCount=0, AnCount=1, NsCount=0, ArCount=0 }",

         /* ID */ 0x5006,
         /* QR_Flag */ true, /* AA_Flag */ false, /* TC_Flag */ false, /* RD_Flag */ false, /* RA_Flag */ false, /* AD_Flag */ false, /* CD_Flag */ false,
         /* OpCode */ dns::op_code_t::query, /* RCode */ dns::r_code_t::no_error,
         /* QdCount */ 0, /* AnCount */ 1, /* NsCount */ 0, /* ArCount */ 0,
      },

      {
         TEST_CONTEXT("Load response header (with data beyond header)"),
         "\x50\x06\x80\x00\x00\x00\x00\x01\x00\x00\x00\x00ZABCDEFGHIJKLMNOP"s,

         exception_info(),
         12,
         "{ ID=20486, Flags=[QR], OpCode=query, RCode=no_error, QdCount=0, AnCount=1, NsCount=0, ArCount=0 }",

         /* ID */ 0x5006,
         /* QR_Flag */ true, /* AA_Flag */ false, /* TC_Flag */ false, /* RD_Flag */ false, /* RA_Flag */ false, /* AD_Flag */ false, /* CD_Flag */ false,
         /* OpCode */ dns::op_code_t::query, /* RCode */ dns::r_code_t::no_error,
         /* QdCount */ 0, /* AnCount */ 1, /* NsCount */ 0, /* ArCount */ 0,
      },

      {
         TEST_CONTEXT("Load a truncated response header"),
         "\x50\x06\x80\x00\x00\x00\x00\x01\x00\x00\x00"s,

         exception_info<dns::exception::bad_data_stream>("truncated"s, 1),
         11,
         "",
      },

      {
         TEST_CONTEXT("Load response header with RCode"),
         "\x50\x06\x80\x09\x00\x00\x00\x01\x00\x00\x00\x00ZABCDEFGHIJKLMNOP"s,

         exception_info(),
         12,
         "{ ID=20486, Flags=[QR], OpCode=query, RCode=not_auth, QdCount=0, AnCount=1, NsCount=0, ArCount=0 }",

         /* ID */ 0x5006,
         /* QR_Flag */ true, /* AA_Flag */ false, /* TC_Flag */ false, /* RD_Flag */ false, /* RA_Flag */ false, /* AD_Flag */ false, /* CD_Flag */ false,
         /* OpCode */ dns::op_code_t::query, /* RCode */ dns::r_code_t::not_auth,
         /* QdCount */ 0, /* AnCount */ 1, /* NsCount */ 0, /* ArCount */ 0,
      },

      {
         TEST_CONTEXT("Load query header with RD"),
         "\xf9\xac\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00ZABCDEFGHIJKLMNOP"s,

         exception_info(),
         12,
         "{ ID=63916, Flags=[RD], OpCode=query, RCode=no_error, QdCount=1, AnCount=0, NsCount=0, ArCount=0 }",

         /* ID */ 0xf9ac,
         /* QR_Flag */ false, /* AA_Flag */ false, /* TC_Flag */ false, /* RD_Flag */ true, /* RA_Flag */ false, /* AD_Flag */ false, /* CD_Flag */ false,
         /* OpCode */ dns::op_code_t::query, /* RCode */ dns::r_code_t::no_error,
         /* QdCount */ 1, /* AnCount */ 0, /* NsCount */ 0, /* ArCount */ 0,
      },

      {
         TEST_CONTEXT("Load query header with OpCode"),
         "\xf9\xac\x10\x00\x00\x01\x00\x00\x00\x00\x00\x00ZABCDEFGHIJKLMNOP"s,

         exception_info(),
         12,
         "{ ID=63916, Flags=[], OpCode=status, RCode=no_error, QdCount=1, AnCount=0, NsCount=0, ArCount=0 }",

         /* ID */ 0xf9ac,
         /* QR_Flag */ false, /* AA_Flag */ false, /* TC_Flag */ false, /* RD_Flag */ false, /* RA_Flag */ false, /* AD_Flag */ false, /* CD_Flag */ false,
         /* OpCode */ dns::op_code_t::status, /* RCode */ dns::r_code_t::no_error,
         /* QdCount */ 1, /* AnCount */ 0, /* NsCount */ 0, /* ArCount */ 0,
      },

      {
         TEST_CONTEXT("Load response header with AA"),
         "\x11\x11\x84\x00\x00\x00\x00\x00\x00\x01\x00\x00ZABCDEFGHIJKLMNOP"s,

         exception_info(),
         12,
         "{ ID=4369, Flags=[QR,AA], OpCode=query, RCode=no_error, QdCount=0, AnCount=0, NsCount=1, ArCount=0 }",

         /* ID */ 0x1111,
         /* QR_Flag */ true, /* AA_Flag */ true, /* TC_Flag */ false, /* RD_Flag */ false, /* RA_Flag */ false, /* AD_Flag */ false, /* CD_Flag */ false,
         /* OpCode */ dns::op_code_t::query, /* RCode */ dns::r_code_t::no_error,
         /* QdCount */ 0, /* AnCount */ 0, /* NsCount */ 1, /* ArCount */ 0,
      },

      {
         TEST_CONTEXT("Load response header with TC"),
         "\xFF\xFF\x82\x00\x00\x00\x00\x00\x00\x00\x00\x01ZABCDEFGHIJKLMNOP"s,

         exception_info(),
         12,
         "{ ID=65535, Flags=[QR,TC], OpCode=query, RCode=no_error, QdCount=0, AnCount=0, NsCount=0, ArCount=1 }",

         /* ID */ 0xFFFF,
         /* QR_Flag */ true, /* AA_Flag */ false, /* TC_Flag */ true, /* RD_Flag */ false, /* RA_Flag */ false, /* AD_Flag */ false, /* CD_Flag */ false,
         /* OpCode */ dns::op_code_t::query, /* RCode */ dns::r_code_t::no_error,
         /* QdCount */ 0, /* AnCount */ 0, /* NsCount */ 0, /* ArCount */ 1,
      },

      {
         TEST_CONTEXT("Load response header with RA"),
         "\xFF\xFF\x80\x80\x00\x00\x00\x00\x00\x00\x00\x01ZABCDEFGHIJKLMNOP"s,

         exception_info(),
         12,
         "{ ID=65535, Flags=[QR,RA], OpCode=query, RCode=no_error, QdCount=0, AnCount=0, NsCount=0, ArCount=1 }",

         /* ID */ 0xFFFF,
         /* QR_Flag */ true, /* AA_Flag */ false, /* TC_Flag */ false, /* RD_Flag */ false, /* RA_Flag */ true, /* AD_Flag */ false, /* CD_Flag */ false,
         /* OpCode */ dns::op_code_t::query, /* RCode */ dns::r_code_t::no_error,
         /* QdCount */ 0, /* AnCount */ 0, /* NsCount */ 0, /* ArCount */ 1,
      },

      {
         TEST_CONTEXT("Load response header with AD"),
         "\xFF\xFF\x80\x20\x00\x00\x00\x00\x00\x00\x00\x01ZABCDEFGHIJKLMNOP"s,

         exception_info(),
         12,
         "{ ID=65535, Flags=[QR,AD], OpCode=query, RCode=no_error, QdCount=0, AnCount=0, NsCount=0, ArCount=1 }",

         /* ID */ 0xFFFF,
         /* QR_Flag */ true, /* AA_Flag */ false, /* TC_Flag */ false, /* RD_Flag */ false, /* RA_Flag */ false, /* AD_Flag */ true, /* CD_Flag */ false,
         /* OpCode */ dns::op_code_t::query, /* RCode */ dns::r_code_t::no_error,
         /* QdCount */ 0, /* AnCount */ 0, /* NsCount */ 0, /* ArCount */ 1,
      },

      {
         TEST_CONTEXT("Load response header with CD"),
         "\xFF\xFF\x80\x10\x00\x00\x00\x00\x00\x00\x00\x01ZABCDEFGHIJKLMNOP"s,

         exception_info(),
         12,
         "{ ID=65535, Flags=[QR,CD], OpCode=query, RCode=no_error, QdCount=0, AnCount=0, NsCount=0, ArCount=1 }",

         /* ID */ 0xFFFF,
         /* QR_Flag */ true, /* AA_Flag */ false, /* TC_Flag */ false, /* RD_Flag */ false, /* RA_Flag */ false, /* AD_Flag */ false, /* CD_Flag */ true,
         /* OpCode */ dns::op_code_t::query, /* RCode */ dns::r_code_t::no_error,
         /* QdCount */ 0, /* AnCount */ 0, /* NsCount */ 0, /* ArCount */ 1,
      },
   };

   /////////////////////////////////////////////////////

   for(auto Datum : TestData)
   {
      BOOST_TEST_CONTEXT(Datum.test_context)
      {
         if( boost::algorithm::contains(Datum.test_context, "GDB:") )
            BOOST_TEST_MESSAGE( getpid() ), sleep(30);

         auto pH = make_my_unique<dns::header_t>(); // TEST OBJECT

         /// Set
         {
            pH->ID(0xFFFF);
            pH->QR_Flag(true);
            pH->AA_Flag(true);
            pH->TC_Flag(true);
            pH->RD_Flag(true);
            pH->RA_Flag(true);
            pH->AD_Flag(true);
            pH->CD_Flag(true);

            pH->OpCode(static_cast<dns::op_code_t>(0xFF));
            pH->RCode(static_cast<dns::r_code_t>(0xFF));

            pH->QdCount(0xFFFF);
            pH->AnCount(0xFFFF);
            pH->NsCount(0xFFFF);
            pH->ArCount(0xFFFF);
         }

         if(Datum.expected_exception)
         {
            auto&& b = Datum.input_raw_data.begin();
            auto&& e = Datum.input_raw_data.end();

            dns::name_offset_tracker_t tr;

            BOOST_CHECK_EXCEPTION( dns::load_from(tr, b, e, *pH), std::exception, Datum.expected_exception); // THE TEST

            BOOST_CHECK(0 <= std::distance(Datum.input_raw_data.begin(), b) && std::distance(Datum.input_raw_data.begin(), b) <= Datum.expected_distance);
         }
         else
         {
            auto&& b = Datum.input_raw_data.begin();
            auto&& e = Datum.input_raw_data.end();

            dns::name_offset_tracker_t tr;

            BOOST_CHECK_NO_THROW( dns::load_from(tr, b, e, *pH)); // THE TEST

            BOOST_CHECK_EQUAL(std::distance(Datum.input_raw_data.begin(), b), Datum.expected_distance);

            std::vector<uint8_t> store;

            {
               auto&& o = std::back_inserter(store);

               dns::name_offset_tracker_t tr;

               BOOST_CHECK_NO_THROW(save_to(tr, o, *pH));
            }

            BOOST_CHECK_EQUAL(util::oct_dump(store), util::oct_dump(Datum.input_raw_data.substr(0, Datum.expected_distance)));

            BOOST_CHECK_NO_THROW(BOOST_CHECK_EQUAL(static_cast<std::ostringstream&>(std::ostringstream() << *pH).str(), Datum.expected_stream));

            // More Check
            {
               BOOST_CHECK_EQUAL(pH->ID(),      Datum.expected_ID);

               BOOST_CHECK_EQUAL(pH->QR_Flag(), Datum.expected_QR_Flag);
               BOOST_CHECK_EQUAL(pH->AA_Flag(), Datum.expected_AA_Flag);
               BOOST_CHECK_EQUAL(pH->TC_Flag(), Datum.expected_TC_Flag);
               BOOST_CHECK_EQUAL(pH->RD_Flag(), Datum.expected_RD_Flag);
               BOOST_CHECK_EQUAL(pH->RA_Flag(), Datum.expected_RA_Flag);
               BOOST_CHECK_EQUAL(pH->AD_Flag(), Datum.expected_AD_Flag);
               BOOST_CHECK_EQUAL(pH->CD_Flag(), Datum.expected_CD_Flag);

               BOOST_CHECK_EQUAL(pH->OpCode(),  Datum.expected_OpCode);
               BOOST_CHECK_EQUAL(pH->RCode(),   Datum.expected_RCode);
               BOOST_CHECK_EQUAL(pH->Res1_Flag(),   0);

               BOOST_CHECK_EQUAL(pH->QdCount(), Datum.expected_QdCount);
               BOOST_CHECK_EQUAL(pH->AnCount(), Datum.expected_AnCount);
               BOOST_CHECK_EQUAL(pH->NsCount(), Datum.expected_NsCount);
               BOOST_CHECK_EQUAL(pH->ArCount(), Datum.expected_ArCount);
            }
         }
      }
   }
}
