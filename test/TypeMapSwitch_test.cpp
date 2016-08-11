#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE TypeMapSwitch_test
#include <boost/test/unit_test.hpp>

#include "util/TypeMapSwitch.h"

#include "test/test_context.h"

#include <string>

namespace
{
   template<typename T>
   struct WorkImpl
   {
      template<typename F>
      void operator()(F&& fu)
      {
         fu((T*)(nullptr));
      }
   };

   template<>
   struct WorkImpl<void>
   {
      template<typename F>
      void operator()(F&& fu)
      {
         fu((void*)(nullptr));
      }
   };

   enum class ABC_t
   {
      OPT1 = 25,
      OPT2 = 10,
      OPT3 = 15,
      OPT4 = 29,
      OPT5 = 26,
      OPT6 = 36,
      OPT7 = 46,
   };
}

BOOST_AUTO_TEST_CASE(basic_use)
{
   using namespace util;
   using TMS = TypeMapSwitch_t< TypeMap<ABC_t, ABC_t::OPT1, int>, TypeMap<ABC_t, ABC_t::OPT5, float>, TypeMap<ABC_t, ABC_t::OPT2, long>, TypeMap<ABC_t, ABC_t::OPT7, std::string> >;

   int x = 0;
   int y = 1;

   TMS::dispatch<WorkImpl>(
      ABC_t::OPT5,
      [&x](auto z)
   {
      BOOST_CHECK_EQUAL(typeid(z).name(), typeid(float*).name());
      ++x;
   });
   BOOST_CHECK_EQUAL(x, 1);

   TMS::dispatch<WorkImpl>(
      ABC_t::OPT1,
      [&x, y](auto z)
   {
      BOOST_CHECK_EQUAL(typeid(z).name(), typeid(int*).name());
      x += y;
   });
   BOOST_CHECK_EQUAL(x, 2);

   TMS::dispatch<WorkImpl>(
      ABC_t::OPT2,
      [&x, y](auto z)
   {
      BOOST_CHECK_EQUAL(typeid(z).name(), typeid(long*).name());
      x += y;
   });
   BOOST_CHECK_EQUAL(x, 3);

   TMS::dispatch<WorkImpl>(
      ABC_t::OPT6,
      [&x, y](auto z)
   {
      BOOST_CHECK_EQUAL(typeid(z).name(), typeid(void*).name());
      x += y;
   });
   BOOST_CHECK_EQUAL(x, 4);

   TMS::dispatch<WorkImpl>(
      ABC_t::OPT7,
      [&x, y](auto z)
   {
      BOOST_CHECK_EQUAL(typeid(z).name(), typeid(std::string*).name());
      x += y;
   });
   BOOST_CHECK_EQUAL(x, 5);

   // How to verify if the switch is happing using binary search
}
