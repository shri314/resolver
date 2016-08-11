#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE TypeList_test
#include <boost/test/unit_test.hpp>

#include "util/TypeList.h"

#include <string>

namespace
{
   template<class T>
   struct Wrapper
   {
   };
};


template<class T1, class T2>
void CheckExpectedType()
{
   BOOST_CHECK_EQUAL(boost::core::demangle(typeid(Wrapper<T1>).name()), boost::core::demangle(typeid(Wrapper<T2>).name()));
}


BOOST_AUTO_TEST_CASE(Size_v_test)
{
   using namespace util;

   {
      using TL = TypeList<>;

      BOOST_CHECK_EQUAL(Size_v<TL>, 0);
   }

   {
      using TL = TypeList<int>;

      BOOST_CHECK_EQUAL(Size_v<TL>, 1);
   }

   {
      using TL = TypeList < int, int&, int*, int&&, const int*, int* const, const int* const, float, long, std::string, long >;

      BOOST_CHECK_EQUAL(Size_v<TL>, 11);
   }
}


BOOST_AUTO_TEST_CASE(Access_t_test)
{
   using namespace util;

   {
      // using TL = TypeList<>;

      // CheckExpectedType< Access_t<TL, 0>, ?? >();
   }

   {
      using TL = TypeList<int>;

      CheckExpectedType< Access_t<TL, 0>, int >();
   }

   {
      using TL = TypeList < int, int&, int*, int&&, const int*, int* const, const int* const, float, long, std::string, long >;

      CheckExpectedType< Access_t<TL, 0>, int >();
      CheckExpectedType< Access_t<TL, 1>, int& >();
      CheckExpectedType< Access_t<TL, 2>, int* >();
      CheckExpectedType< Access_t<TL, 3>, int&& > ();
      CheckExpectedType< Access_t<TL, 4>, const int* >();
      CheckExpectedType< Access_t<TL, 5>, int* const >();
      CheckExpectedType< Access_t<TL, 6>, const int* const >();
      CheckExpectedType< Access_t<TL, 7>, float >();
      CheckExpectedType< Access_t<TL, 8>, long >();
      CheckExpectedType< Access_t<TL, 9>, std::string >();  // non pod types are okay
      CheckExpectedType< Access_t<TL, 10>, long >();        // types can repeat

      // CheckExpectedType< Access_t<TL, 11>, ?? >();        // types can repeat
   }
}


BOOST_AUTO_TEST_CASE(Front_t_test)
{
   using namespace util;

   {
      // using TL = TypeList<>;

      // CheckExpectedType< Front_t<TL>, ?? >();
   }

   {
      using TL = TypeList<int>;

      CheckExpectedType< Front_t<TL>, int >();
   }

   {
      using TL = TypeList < int, int&, int*, int&&, long >;

      CheckExpectedType< Front_t<TL>, int >();
   }
}


BOOST_AUTO_TEST_CASE(Join_t_test)
{
   using namespace util;

   using TL = TypeList<>;
   using TL1 = TypeList<int>;
   using TL2 = TypeList<float, long>;

   CheckExpectedType< Join_t< TL, TL >, TL >();
   CheckExpectedType< Join_t< TL, TL1 >, TL1 >();
   CheckExpectedType< Join_t< TL1, TL >, TL1 >();
   CheckExpectedType< Join_t< TL1, TL1 >, TypeList<int, int> >();
   CheckExpectedType< Join_t< TL1, TL2 >, TypeList<int, float, long> >();
   CheckExpectedType< Join_t< TL2, TL1 >, TypeList<float, long, int> >();
   CheckExpectedType< Join_t< TL2, TL2 >, TypeList<float, long, float, long> >();
}


BOOST_AUTO_TEST_CASE(PopFront_t_test)
{
   using namespace util;

   {
      // using TL = TypeList<>;

      // CheckExpectedType< PopFront_t< TL >, ?? >();
   }

   {
      using TL = TypeList<int>;

      CheckExpectedType< PopFront_t< TL >, TypeList<> >();
   }

   {
      using TL = TypeList < int, int&, int*, int&& >;

      CheckExpectedType < PopFront_t<TL>, TypeList < int&, int*, int&& > > ();
      CheckExpectedType < PopFront_t< PopFront_t<TL>> , TypeList < int*, int&& > > ();
      CheckExpectedType < PopFront_t<PopFront_t< PopFront_t<TL>>> , TypeList < int&& > > ();
      CheckExpectedType < PopFront_t<PopFront_t<PopFront_t< PopFront_t<TL>>>> , TypeList<> > ();
   }
}


BOOST_AUTO_TEST_CASE(Slice_t_test)
{
   using namespace util;

   {
      using TL = TypeList<>;

      CheckExpectedType< Slice_t<TL, 0, 0>, TypeList<> >();
      CheckExpectedType< Slice_t<TL, 0, 10>, TypeList<> >();
      // CheckExpectedType< Slice_t<TL, 1, 0>, ?? >();
      // CheckExpectedType< Slice_t<TL, 1, 10>, ?? >();
   }

   {
      using TL = TypeList<int>;

      CheckExpectedType< Slice_t<TL, 0, 0>, TypeList<> >();
      CheckExpectedType< Slice_t<TL, 0, 10>, TypeList<int> >();
      CheckExpectedType< Slice_t<TL, 1, 10>, TypeList<> >();
      // CheckExpectedType< Slice_t<TL, 2, 10>, ?? >();
   }

   {
      using TL = TypeList < int, int&, int*, int&& >;

      CheckExpectedType< Slice_t<TL, 0, 0>, TypeList<> >();
      CheckExpectedType< Slice_t<TL, 0, 1>, TypeList<int> >();
      CheckExpectedType< Slice_t<TL, 0, 2>, TypeList<int, int&> >();
      CheckExpectedType< Slice_t<TL, 0, 3>, TypeList<int, int&, int*> >();
      CheckExpectedType < Slice_t<TL, 0, 4>, TypeList < int, int&, int*, int&& > > ();
      CheckExpectedType < Slice_t<TL, 0, 5>, TypeList < int, int&, int*, int&& > > ();
      CheckExpectedType < Slice_t<TL, 0, 10>, TypeList < int, int&, int*, int&& > > ();

      CheckExpectedType< Slice_t<TL, 1, 0>, TypeList<> >();
      CheckExpectedType< Slice_t<TL, 1, 1>, TypeList<int&> >();
      CheckExpectedType< Slice_t<TL, 1, 2>, TypeList<int&, int*> >();
      CheckExpectedType < Slice_t<TL, 1, 3>, TypeList < int&, int*, int&& > > ();
      CheckExpectedType < Slice_t<TL, 1, 4>, TypeList < int&, int*, int&& > > ();
      CheckExpectedType < Slice_t<TL, 1, 10>, TypeList < int&, int*, int&& > > ();

      CheckExpectedType< Slice_t<TL, 2, 0>, TypeList<> >();
      CheckExpectedType< Slice_t<TL, 2, 1>, TypeList<int*> >();
      CheckExpectedType < Slice_t<TL, 2, 2>, TypeList < int*, int&& > > ();
      CheckExpectedType < Slice_t<TL, 2, 3>, TypeList < int*, int&& > > ();
      CheckExpectedType < Slice_t<TL, 2, 10>, TypeList < int*, int&& > > ();

      CheckExpectedType< Slice_t<TL, 3, 0>, TypeList<> >();
      CheckExpectedType < Slice_t<TL, 3, 1>, TypeList < int&& > > ();
      CheckExpectedType < Slice_t<TL, 3, 2>, TypeList < int&& > > ();
      CheckExpectedType < Slice_t<TL, 3, 10>, TypeList < int&& > > ();

      CheckExpectedType< Slice_t<TL, 4, 0>, TypeList<> >();
      CheckExpectedType< Slice_t<TL, 4, 1>, TypeList<> >();
      CheckExpectedType< Slice_t<TL, 4, 10>, TypeList<> >();

      // CheckExpectedType< Slice_t<TL, 5, 0>, ?? >();
      // CheckExpectedType< Slice_t<TL, 5, 1>, ?? >();
   }
}

namespace
{
   template<int x>
   struct I;

   template<class L, class R>
   struct LtTypeCmp;

   template<int xx, int yy>
   struct LtTypeCmp< I<xx>, I<yy> >
   {
      constexpr static auto value = xx < yy;
   };
}


BOOST_AUTO_TEST_CASE(Merge_t_test)
{
   using namespace util;

   {
      using TL1 = TypeList<>;
      using TL2 = TypeList<>;

      CheckExpectedType< Merge_t<TL1, TL2, LtTypeCmp>, TypeList<> >();
   }

   {
      using TL1 = TypeList< I<1> >;
      using TL2 = TypeList<>;

      CheckExpectedType< Merge_t<TL1, TL2, LtTypeCmp>, TypeList< I<1> > >();
   }

   {
      using TL1 = TypeList<>;
      using TL2 = TypeList< I<1> >;

      CheckExpectedType< Merge_t<TL1, TL2, LtTypeCmp>, TypeList< I<1> > >();
   }

   {
      using TL1 = TypeList< I<1> >;
      using TL2 = TypeList< I<2> >;

      CheckExpectedType< Merge_t<TL1, TL2, LtTypeCmp>, TypeList< I<1>, I<2> > >();
   }

   {
      using TL1 = TypeList< I<2> >;
      using TL2 = TypeList< I<1> >;

      CheckExpectedType< Merge_t<TL1, TL2, LtTypeCmp>, TypeList< I<1>, I<2> > >();
   }

   {
      using TL1 = TypeList< I<1> >;
      using TL2 = TypeList< I<2>, I<4> >;

      CheckExpectedType< Merge_t<TL1, TL2, LtTypeCmp>, TypeList< I<1>, I<2>, I<4> > >();
   }

   {
      using TL1 = TypeList< I<3> >;
      using TL2 = TypeList< I<2>, I<4> >;

      CheckExpectedType< Merge_t<TL1, TL2, LtTypeCmp>, TypeList< I<2>, I<3>, I<4> > >();
   }

   {
      using TL1 = TypeList< I<5> >;
      using TL2 = TypeList< I<2>, I<4> >;

      CheckExpectedType< Merge_t<TL1, TL2, LtTypeCmp>, TypeList< I<2>, I<4>, I<5> > >();
   }

   {
      using TL1 = TypeList< I<1>, I<3> >;
      using TL2 = TypeList< I<2>, I<4> >;

      CheckExpectedType< Merge_t<TL1, TL2, LtTypeCmp>, TypeList< I<1>, I<2>, I<3>, I<4> > >();
   }

   {
      using TL1 = TypeList< I<1>, I<3>, I<5> >;
      using TL2 = TypeList< I<2>, I<4>, I<6> >;

      CheckExpectedType< Merge_t<TL1, TL2, LtTypeCmp>, TypeList< I<1>, I<2>, I<3>, I<4>, I<5>, I<6> > >();
   }

   {
      using TL1 = TypeList< I<1>, I<7> >;
      using TL2 = TypeList< I<2>, I<4>, I<6> >;

      CheckExpectedType< Merge_t<TL1, TL2, LtTypeCmp>, TypeList< I<1>, I<2>, I<4>, I<6>, I<7> > >();
   }
}


BOOST_AUTO_TEST_CASE(Sort_t_test)
{
   using namespace util;

   {
      using TL = TypeList<>;

      CheckExpectedType< Sort_t<TL, LtTypeCmp>, TypeList<> >();
   }

   {
      using TL = TypeList< I<1> >;

      CheckExpectedType< Sort_t<TL, LtTypeCmp>, TypeList< I<1> > >();
   }

   {
      using TL = TypeList< I<1>, I<3> >;

      CheckExpectedType< Sort_t<TL, LtTypeCmp>, TypeList< I<1>, I<3> > >();
   }

   {
      using TL = TypeList< I<3>, I<1> >;

      CheckExpectedType< Sort_t<TL, LtTypeCmp>, TypeList< I<1>, I<3> > >();
   }

   {
      using TL = TypeList< I<1>, I<7>, I<3> >;

      CheckExpectedType< Sort_t<TL, LtTypeCmp>, TypeList< I<1>, I<3>, I<7> > >();
   }

   {
      using TL = TypeList< I<1>, I<7>, I<5>, I<3> >;

      CheckExpectedType< Sort_t<TL, LtTypeCmp>, TypeList< I<1>, I<3>, I<5>, I<7> > >();
   }
}
