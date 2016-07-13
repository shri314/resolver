#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE Dns_test
#include <boost/test/unit_test.hpp>

#include "dns/label_list.h"

#include "test_context.h"
#include "raw_dump.h"

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


BOOST_AUTO_TEST_CASE(dns_label_list_t_save_to)
{
   struct
   {
      std::string test_context;
      std::string input_name;
      uint16_t input_ptr_offset;

      exception_info_t expected_exception;
      std::string expected_name;
      std::string expected_stream;
      std::string expected_raw_data;
   }
   TestData[] =
   {
      {
         TEST_CONTEXT("empty"),
         "",
         0,

         exception_info(),
         "",
         "[]",
         "\0"s,
      },

      {
         TEST_CONTEXT("empty + ptr_offset"),
         "",
         45,

         exception_info(),
         "",
         "[]->[45]",
         "\300\55"s,
      },

      {
         TEST_CONTEXT("empty + ptr_offset which fits"),
         "",
         16383,

         exception_info(),
         "",
         "[]->[16383]",
         "\xFF\xFF"s,
      },

      {
         TEST_CONTEXT("simple case"),
         "www.yahoo.com",
         0,

         exception_info(),
         "www.yahoo.com",
         "[www.yahoo.com]",
         "\3www\5yahoo\3com\0"s,
      },

      {
         TEST_CONTEXT("simple case + ptr_offset"),
         "www.yahoo.com",
         45,

         exception_info(),
         "www.yahoo.com",
         "[www.yahoo.com]->[45]",
         "\3www\5yahoo\3com\300\55"s,
      },

      {
         TEST_CONTEXT("with single ending dot"),
         "www.yahoo.com.",
         0,

         exception_info(),
         "www.yahoo.com",
         "[www.yahoo.com]",
         "\3www\5yahoo\3com\0"s,
      },

      {
         TEST_CONTEXT("with single ending dot + ptr_offset"),
         "www.yahoo.com.",
         45,

         exception_info(),
         "www.yahoo.com",
         "[www.yahoo.com]->[45]",
         "\3www\5yahoo\3com\300\55"s,
      },

      {
         TEST_CONTEXT("bad ptr_offset"),
         "www.yahoo.com",
         16384,

         exception_info<dns::exception::bad_ptr_offset>("offset too long"s, 1),
         "",
         "",
         "",
      },

      {
         TEST_CONTEXT("with extra ending dots"),
         "www.yahoo.com..",
         0,

         exception_info<dns::exception::bad_name>("wrong format"s, 1),
         "",
         "",
         "",
      },

      {
         TEST_CONTEXT("with extra dots"),
         "www.yahoo..com",
         0,

         exception_info<dns::exception::bad_name>("wrong format"s, 1),
         "",
         "",
         "",
      },

      {
         TEST_CONTEXT("below 63 label limit"),
         std::string(63, 'w') + ".com",
         0,

         exception_info(),
         std::string(63, 'w') + ".com",
         "[" + std::string(63, 'w') + ".com" + "]",
         "\77"s + std::string(63, 'w') + "\3com\0"s,
      },

      {
         TEST_CONTEXT("below 63 label limit + ptr_offset"),
         std::string(63, 'w') + ".com",
         45,

         exception_info(),
         std::string(63, 'w') + ".com",
         "[" + std::string(63, 'w') + ".com" + "]->[45]",
         "\77"s + std::string(63, 'w') + "\3com\300\55"s,
      },

      {
         TEST_CONTEXT("beyond 63 label limit"),
         std::string(63, 'w') + "X.com",
         0,

         exception_info<dns::exception::bad_name>("length too long"s, 1),
         "",
         "",
         "",
      },

      {
         TEST_CONTEXT("below 255 limit"),
         std::string(077, 'w') + '.' + std::string(077, 'a') + '.' + std::string(077, 'b') + '.' + std::string(075, 'c'),
         0,

         exception_info(),
         std::string(077, 'w') + '.' + std::string(077, 'a') + '.' + std::string(077, 'b') + '.' + std::string(075, 'c'),
         "[" + std::string(077, 'w') + '.' + std::string(077, 'a') + '.' + std::string(077, 'b') + '.' + std::string(075, 'c') + "]",
         "\77"s + std::string(077, 'w') + "\077"s + std::string(077, 'a') + "\077"s + std::string(077, 'b') + "\075"s + std::string(075, 'c') + "\0"s,
      },

      {
         TEST_CONTEXT("below 255 limit + ptr_offset"),
         std::string(077, 'w') + '.' + std::string(077, 'a') + '.' + std::string(077, 'b') + '.' + std::string(074, 'c'),
         45,

         exception_info(),
         std::string(077, 'w') + '.' + std::string(077, 'a') + '.' + std::string(077, 'b') + '.' + std::string(074, 'c'),
         "[" + std::string(077, 'w') + '.' + std::string(077, 'a') + '.' + std::string(077, 'b') + '.' + std::string(074, 'c') + "]->[45]",
         "\77"s + std::string(077, 'w') + "\077"s + std::string(077, 'a') + "\077"s + std::string(077, 'b') + "\074"s + std::string(074, 'c') + "\300\55"s,
      },

      {
         TEST_CONTEXT("beyond 255 limit (no room for chars)"),
         std::string(077, 'w') + '.' + std::string(077, 'a') + '.' + std::string(077, 'b') + '.' + std::string(070, 'c') + '.' + std::string(06, 'd'),
         0,

         exception_info<dns::exception::bad_name>("length too long"s, 2),
         "",
         "",
         "",
      },

      {
         TEST_CONTEXT("beyond 255 limit (no room for internal \\0)"),
         std::string(077, 'w') + '.' + std::string(077, 'a') + '.' + std::string(077, 'b') + '.' + std::string(075, 'c') + 'X',
         0,

         exception_info<dns::exception::bad_name>("length too long"s, 3),
         "",
         "",
         "",
      },

      {
         TEST_CONTEXT("beyond 255 limit (no room for internal ptr_offset)"),
         std::string(077, 'w') + '.' + std::string(077, 'a') + '.' + std::string(077, 'b') + '.' + std::string(074, 'c') + 'X',
         45,

         exception_info<dns::exception::bad_name>("length too long"s, 3),
         "",
         "",
         "",
      },
   };

   /////////////////////////////////////////////////////

   for(auto Datum : TestData)
   {
      BOOST_TEST_CONTEXT(Datum.test_context)
      {
         auto pQN = make_my_unique<dns::label_list_t>();    // TEST OBJECT

         BOOST_CHECK_NO_THROW(pQN->Name(Datum.input_name)); // THE TEST

         BOOST_CHECK_EQUAL(pQN->Name(), Datum.expected_name);

         BOOST_CHECK_NO_THROW(BOOST_CHECK_EQUAL(static_cast<std::ostringstream&>(std::ostringstream() << *pQN).str(), Datum.expected_stream));

         {
            std::string store;
            auto&& o = std::back_inserter(store);

            dns::name_offset_tracker_t no_tr{Datum.input_ptr_offset};

            if(Datum.expected_exception)
            {
               BOOST_CHECK_EXCEPTION(dns::save_to(o, no_tr, *pQN), std::exception, Datum.expected_exception);   // THE TEST
            }
            else
            {
               BOOST_CHECK_NO_THROW(dns::save_to(o, no_tr, *pQN));   // THE TEST

               BOOST_CHECK_EQUAL(OctRep(store), OctRep(Datum.expected_raw_data));
            }
         }
      }
   }
}


BOOST_AUTO_TEST_CASE(dns_label_list_t_load_from)
{
}
