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

BOOST_AUTO_TEST_CASE(dns_save_to_and_load_from)
{
   struct
   {
      std::string test_context;

      std::string input_Name;
      dns::rr_type_t input_Type;
      dns::rr_class_t input_Class;
      uint32_t input_TTL;
      boost::any input_Rec;

      std::string expected_raw_data;
      std::string expected_stream;
   }
   TestData[] =
   {
      {
         TEST_CONTEXT("a case"),
         "www.google.com", dns::rr_type_t::rec_a, dns::rr_class_t::internet, 131073u, dns::rec_a_t{"216.58.220.4"},

         "\3www\6google\3com\0\0\1\0\1\0\2\0\1\0\4\330:\334\4"s,
         "{ Name=www.google.com, Type=a, Class=internet, TTL=131073, REC=[216.58.220.4] }",
      },

      {
         TEST_CONTEXT("mx case"),
         "www.yahoo.com", dns::rr_type_t::rec_mx, dns::rr_class_t::internet, 131073u, dns::rec_mx_t{10, "mx1.yahoo.com"},

         "\3www\5yahoo\3com\0\0\17\0\1\0\2\0\1\0\10\0\n\3mx1\300\4"s,
         "{ Name=www.yahoo.com, Type=mx, Class=internet, TTL=131073, REC=[preference=10, exchange=mx1.yahoo.com] }",
      },

      {
         TEST_CONTEXT("ptr case"),
         "36.102.85.209.in-addr.arpa", dns::rr_type_t::rec_ptr, dns::rr_class_t::internet, 131073u, dns::rec_ptr_t{"serv01.siteground.com"},

         "\00236\003102\00285\003209\7in-addr\4arpa\0\0\f\0\1\0\2\0\1\0\27\6serv01\nsiteground\3com\0"s,
         "{ Name=36.102.85.209.in-addr.arpa, Type=ptr, Class=internet, TTL=131073, REC=[serv01.siteground.com] }",
      },

      {
         TEST_CONTEXT("ns case"),
         "yahoo.com", dns::rr_type_t::rec_ns, dns::rr_class_t::internet, 131073u, dns::rec_ns_t{"ns1.yahoo.com"},

         "\5yahoo\3com\0\0\2\0\1\0\2\0\1\0\6\3ns1\300\0"s,
         "{ Name=yahoo.com, Type=ns, Class=internet, TTL=131073, REC=[ns1.yahoo.com] }",
      },

      {
         TEST_CONTEXT("cname case"),
         "www.google.com", dns::rr_type_t::rec_cname, dns::rr_class_t::internet, 131073u, dns::rec_cname_t{"mail.google.com"},

         "\3www\6google\3com\0\0\5\0\1\0\2\0\1\0\7\4mail\300\4"s,
         "{ Name=www.google.com, Type=cname, Class=internet, TTL=131073, REC=[name=mail.google.com] }",
      },

      {
         TEST_CONTEXT("soa case"),
         "www.google.com", dns::rr_type_t::rec_soa, dns::rr_class_t::internet, 131073u, dns::rec_soa_t{"ns1.google.com", "dns-admin.google.com", 128258932u, 900u, 900u, 1800u, 60u},

         "\3www\6google\3com\0\0\6\0\1\0\2\0\1\0&\3ns1\300\4\tdns-admin\300\4\7\245\23t\0\0\3\204\0\0\3\204\0\0\7\10\0\0\0<"s,
         "{ Name=www.google.com, Type=soa, Class=internet, TTL=131073, REC=[mname=ns1.google.com, rname=dns-admin.google.com, serial=128258932, refresh=900, retry=900, expire=1800, minimum=60] }",
      },

      {
         TEST_CONTEXT("txt case"),
         "google._domainkey.protodave.com", dns::rr_type_t::rec_txt, dns::rr_class_t::internet, 131073u, dns::rec_txt_t{"v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAhArxYH88+A76Gk7/8ENefN5RhMFhoYJp8T3KLPYYpejDI45PKWTO+2r8ZJZOtuk7tsG07bmJyU8PFvU48Lf1xtb4WcFxKKjd7N5MF6JcHD51Xb8XDAJA2ldqxH4hBbw9dRjsT7WBFXbp2x6MSWxgi9f1w+7Z2IFG+AtUjrf8/9N3gLieaZKZT1SEhR8TnhfOmFG0LfMyS0YtfHKrkUkBCEmWBPisB2CcZBShKr6/T8/UB/oZF8XMRd0NOsru9MGx9Yp89jIYS5YRuvbA0/TLgOOiqrSU5Ms1egMwfFyy4BMDUKayZzF6BxNPc/+UoFrYHKRZpyD/kEd4FXNEddlksQIDAQAB"},

         "\6google\n_domainkey\tprotodave\3com\0\0\20\0\1\0\2\0\1\1\234\377v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAhArxYH88+A76Gk7/8ENefN5RhMFhoYJp8T3KLPYYpejDI45PKWTO+2r8ZJZOtuk7tsG07bmJyU8PFvU48Lf1xtb4WcFxKKjd7N5MF6JcHD51Xb8XDAJA2ldqxH4hBbw9dRjsT7WBFXbp2x6MSWxgi9f1w+7Z2IFG+AtUjrf8/9N3gLieaZKZT1SEhR8TnhfOm\233FG0LfMyS0YtfHKrkUkBCEmWBPisB2CcZBShKr6/T8/UB/oZF8XMRd0NOsru9MGx9Yp89jIYS5YRuvbA0/TLgOOiqrSU5Ms1egMwfFyy4BMDUKayZzF6BxNPc/+UoFrYHKRZpyD/kEd4FXNEddlksQIDAQAB"s,
         "{ Name=google._domainkey.protodave.com, Type=txt, Class=internet, TTL=131073, REC=[v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAhArxYH88+A76Gk7/8ENefN5RhMFhoYJp8T3KLPYYpejDI45PKWTO+2r8ZJZOtuk7tsG07bmJyU8PFvU48Lf1xtb4WcFxKKjd7N5MF6JcHD51Xb8XDAJA2ldqxH4hBbw9dRjsT7WBFXbp2x6MSWxgi9f1w+7Z2IFG+AtUjrf8/9N3gLieaZKZT1SEhR8TnhfOmFG0LfMyS0YtfHKrkUkBCEmWBPisB2CcZBShKr6/T8/UB/oZF8XMRd0NOsru9MGx9Yp89jIYS5YRuvbA0/TLgOOiqrSU5Ms1egMwfFyy4BMDUKayZzF6BxNPc/+UoFrYHKRZpyD/kEd4FXNEddlksQIDAQAB] }",
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
         pR->Data(Datum.input_Rec);

         BOOST_CHECK_EQUAL(pR->Name(), Datum.input_Name);
         BOOST_CHECK_EQUAL(pR->Type(), Datum.input_Type);
         BOOST_CHECK_EQUAL(pR->Class(), Datum.input_Class);
         BOOST_CHECK_EQUAL(pR->TTL(), Datum.input_TTL);

         BOOST_CHECK_EQUAL(static_cast<std::ostringstream&>(std::ostringstream() << *pR).str(), Datum.expected_stream);

         {
            auto raw_data = std::string{};

            {
               auto&& tr = dns::name_offset_tracker_t{};

               BOOST_CHECK_NO_THROW(dns::save_to(tr, *pR));


               auto&& store = tr.store();

               raw_data.append(store.begin(), store.end());

               BOOST_CHECK_EQUAL(util::oct_dump(store), util::oct_dump(Datum.expected_raw_data));
            }

            {
               auto pR1 = make_my_unique<dns::record_t>(); // LOAD_FROM TEST OBJECT
               auto&& b = raw_data.begin();
               auto&& e = raw_data.end();
               auto&& tr = dns::name_offset_tracker_t{};

               BOOST_CHECK_NO_THROW(*pR1 = dns::load_from<dns::record_t>(tr, b, e));   // THE SECOND TEST

               BOOST_CHECK_EQUAL(static_cast<std::ostringstream&>(std::ostringstream() << *pR1).str(), Datum.expected_stream);

               BOOST_CHECK_EQUAL(*pR1, *pR);
            }
         }
      }
   }
}



BOOST_AUTO_TEST_CASE(dns_negative_load_from)
{
   struct
   {
      std::string test_context;

      std::string input_raw_data;

      exception_info_t expected_exception;
      int expected_distance;
      std::string expected_Name;
      dns::rr_type_t expected_Type;
      dns::rr_class_t expected_Class;
      uint32_t expected_TTL;
      boost::any expected_Rec;
      std::string expected_stream;
   }
   TestData[] =
   {
      {
         TEST_CONTEXT("Load simple case (with excess data)"),
         "\3www\5yahoo\3com\0\0\17\0\1\0\2\0\1\0\t\0\n\4abcd\300\4_ABCDEFGH"s,

         exception_info(),
         34, "www.yahoo.com", dns::rr_type_t::rec_mx, dns::rr_class_t::internet, 131073u, dns::rec_mx_t{10, "abcd.yahoo.com"},
         "{ Name=www.yahoo.com, Type=mx, Class=internet, TTL=131073, REC=[preference=10, exchange=abcd.yahoo.com] }",
      },
      {
         TEST_CONTEXT("Load simple case (with excess data)"),
         "\3www\6google\3com\0\0\5\0\1\0\2\0\1\0\7\4mail\300\4"s,

         exception_info(),
         33, "www.google.com", dns::rr_type_t::rec_cname, dns::rr_class_t::internet, 131073u, dns::rec_cname_t{"mail.google.com"},
         "{ Name=www.google.com, Type=cname, Class=internet, TTL=131073, REC=[name=mail.google.com] }",
      },

      {
         TEST_CONTEXT("Bad load case (with deficient data available)"),
         "\3www\5yahoo\3com\0\0\17\0\1\0\2\0\1\0\32\0\n\4abcd\300\4"s,

         exception_info<dns::exception::bad_data_stream>("truncated"s, 1),
         34,
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

         if(Datum.expected_exception)
         {
            BOOST_CHECK_EXCEPTION( *pR = dns::load_from<dns::record_t>(tr, b, e), std::exception, Datum.expected_exception); // THE TEST

            BOOST_CHECK(0 <= std::distance(Datum.input_raw_data.begin(), b) && std::distance(Datum.input_raw_data.begin(), b) <= Datum.expected_distance);
         }
         else
         {
            BOOST_REQUIRE_NO_THROW(*pR = dns::load_from<dns::record_t>(tr, b, e));   // THE TEST

            BOOST_CHECK_EQUAL(pR->Name(), Datum.expected_Name);
            BOOST_CHECK_EQUAL(pR->Type(), Datum.expected_Type);
            BOOST_CHECK_EQUAL(pR->Class(), Datum.expected_Class);
            BOOST_CHECK_EQUAL(pR->TTL(), Datum.expected_TTL);

            switch(Datum.expected_Type)
            {
               case dns::rr_type_t::rec_mx:
                  BOOST_CHECK_EQUAL(pR->Data<dns::rec_mx_t>(), boost::any_cast<dns::rec_mx_t>(Datum.expected_Rec));
                  break;

               case dns::rr_type_t::rec_cname:
                  BOOST_CHECK_EQUAL(pR->Data<dns::rec_cname_t>(), boost::any_cast<dns::rec_cname_t>(Datum.expected_Rec));
                  break;

               default:
                  BOOST_REQUIRE_MESSAGE(false, "Test not setup properly for the give type");
            }

            BOOST_CHECK_EQUAL(std::distance(Datum.input_raw_data.begin(), b), Datum.expected_distance);
            BOOST_CHECK_EQUAL(static_cast<std::ostringstream&>(std::ostringstream() << *pR).str(), Datum.expected_stream);
         }
      }
   }
}
