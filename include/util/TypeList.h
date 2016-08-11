#pragma once

#include <cstdint>

namespace util
{
   ////////////////////////////////////////////////////////

   template <typename... TypeT>
   struct TypeList;

   ////////////////////////////////////////////////////////

   namespace detail
   {
      template <typename TypeListT>
      struct Size;

      template <typename FirstT, typename... OtherTs>
      struct Size<TypeList<FirstT, OtherTs...>>
      {
         constexpr static std::size_t value = 1 + Size<TypeList<OtherTs...>>::value;
      };

      template <>
      struct Size<TypeList<>>
      {
         constexpr static std::size_t value = 0;
      };
   }

   template <typename TypeListT>
   constexpr auto Size_v = detail::Size<TypeListT>::value;

   ////////////////////////////////////////////////////////

   namespace detail
   {
      template <typename TypeListT, std::size_t pos>
      struct Access;

      template <typename FirstT, typename... OtherTs, std::size_t pos>
      struct Access<TypeList<FirstT, OtherTs...>, pos>
      {
         using type = typename Access < TypeList<OtherTs...>, pos - 1 >::type;
      };

      template <typename FirstT, typename... OtherTs>
      struct Access<TypeList<FirstT, OtherTs...>, 0>
      {
         using type = FirstT;
      };

      template <std::size_t pos>
      struct Access<TypeList<>, pos>
      {
         static_assert(pos < 0, "index out of bounds");
      };
   }

   template <typename TypeListT, std::size_t pos>
   using Access_t = typename detail::Access<TypeListT, pos>::type;

   ////////////////////////////////////////////////////////

   template <typename TypeListT>
   using Front_t = typename detail::Access<TypeListT, 0>::type;

   ////////////////////////////////////////////////////////

   namespace detail
   {
      template <typename TypeListT>
      struct PopFront;

      template <typename FirstT, typename... OtherTs>
      struct PopFront<TypeList<FirstT, OtherTs...>>
      {
         using type = TypeList<OtherTs...>;
      };

      template <>
      struct PopFront<TypeList<>>;
   }

   template <typename TypeListT>
   using PopFront_t = typename detail::PopFront<TypeListT>::type;

   ////////////////////////////////////////////////////////

   namespace detail
   {
      template <typename LeftTypeListT, typename RightTypeListT>
      struct Join;

      template <typename... LeftTs, typename... RightTs>
      struct Join<TypeList<LeftTs...>, TypeList<RightTs...>>
      {
         using type = TypeList<LeftTs..., RightTs...>;
      };
   }

   template <typename LeftTypeListT, typename RightTypeListT>
   using Join_t = typename detail::Join<LeftTypeListT, RightTypeListT>::type;

   ////////////////////////////////////////////////////////

   namespace detail
   {
      template <typename TypeListT, std::size_t begin, std::size_t sz>
      struct Slice;

      template <typename TypeListT, std::size_t begin, std::size_t sz>
      struct Slice
      {
         static_assert(begin <= Size_v<TypeListT>, "index out of bounds [1]");

         using type = typename Slice < PopFront_t<TypeListT>, begin - 1, sz >::type;
      };

      template <typename TypeListT, std::size_t sz>
      struct Slice<TypeListT, 0, sz>
      {
         using type = Join_t < TypeList<Front_t<TypeListT>>, typename Slice < PopFront_t<TypeListT>, 0, sz - 1 >::type >;
      };

      template <typename FirstT, typename... OtherTs>
      struct Slice<TypeList<FirstT, OtherTs...>, 0, 0>
      {
         using type = TypeList<>;
      };

      template <std::size_t sz>
      struct Slice<TypeList<>, 0, sz>
      {
         using type = TypeList<>;
      };
   }

   template <typename TypeListT, std::size_t begin, std::size_t sz = Size_v<TypeListT>>
   using Slice_t = typename detail::Slice<TypeListT, begin, sz>::type;

   ////////////////////////////////////////////////////////

   namespace detail
   {
      template <typename LeftTypeListT, typename RightTypeListT, template<typename, typename> typename LessThanTypeComparatorT>
      struct Merge;

      template <bool pick_left, typename LeftTypeListT, typename RightTypeListT>
      struct Merge_impl_;

      template <typename LeftTypeListT, typename RightTypeListT>
      struct Merge_impl_<true, LeftTypeListT, RightTypeListT>
      {
         using FrontType = Front_t<LeftTypeListT>;
         using RemainingLeftTypeList = PopFront_t<LeftTypeListT>;
         using RemainingRightTypeList = RightTypeListT;
      };

      template <typename LeftTypeListT, typename RightTypeListT>
      struct Merge_impl_<false, LeftTypeListT, RightTypeListT>
      {
         using FrontType = Front_t<RightTypeListT>;
         using RemainingLeftTypeList = LeftTypeListT;
         using RemainingRightTypeList = PopFront_t<RightTypeListT>;
      };

      template <typename LeftTypeListT, typename RightTypeListT, template<typename, typename> typename LessThanTypeComparatorT>
      struct Merge
      {
         private:
            constexpr static const auto pick_left = LessThanTypeComparatorT< Front_t<LeftTypeListT>, Front_t<RightTypeListT> >::value;

            using FrontType = typename Merge_impl_<pick_left, LeftTypeListT, RightTypeListT>::FrontType;
            using RemainingLeftTypeList = typename Merge_impl_<pick_left, LeftTypeListT, RightTypeListT>::RemainingLeftTypeList;
            using RemainingRightTypeList = typename Merge_impl_<pick_left, LeftTypeListT, RightTypeListT>::RemainingRightTypeList;

         public:
            using type = Join_t< TypeList<FrontType>, typename Merge< RemainingLeftTypeList, RemainingRightTypeList, LessThanTypeComparatorT >::type >;
      };

      template <typename... RightTs, template<typename, typename> typename LessThanTypeComparatorT>
      struct Merge<TypeList<>, TypeList<RightTs...>, LessThanTypeComparatorT>
      {
         using type = TypeList<RightTs...>;
      };

      template <typename... LeftTs, template<typename, typename> typename LessThanTypeComparatorT>
      struct Merge<TypeList<LeftTs...>, TypeList<>, LessThanTypeComparatorT>
      {
         using type = TypeList<LeftTs...>;
      };

      template <template<typename, typename> typename LessThanTypeComparatorT>
      struct Merge<TypeList<>, TypeList<>, LessThanTypeComparatorT>
      {
         using type = TypeList<>;
      };
   }

   template <typename LeftTypeListT, typename RightTypeListT, template<typename, typename> typename LessThanTypeComparatorT>
   using Merge_t = typename detail::Merge<LeftTypeListT, RightTypeListT, LessThanTypeComparatorT>::type;

   ////////////////////////////////////////////////////////

   namespace detail
   {
      template<typename TypeListT, template<typename, typename> typename LessThanTypeComparatorT>
      struct Sort;

      template<typename TypeListT, template<typename, typename> typename LessThanTypeComparatorT>
      struct Sort
      {
         private:
            constexpr static const auto mid_pos = Size_v<TypeListT> / 2;

            using SortedLeftHalfTypeList = typename Sort< Slice_t<TypeListT, 0, mid_pos>, LessThanTypeComparatorT >::type;
            using SortedRightHalfTypeList = typename Sort< Slice_t<TypeListT, mid_pos>, LessThanTypeComparatorT >::type;

         public:
            using type = Merge_t< SortedLeftHalfTypeList, SortedRightHalfTypeList, LessThanTypeComparatorT>;
      };

      template<bool c, typename F, typename S>
      struct Select_impl_;

      template<typename F, typename S>
      struct Select_impl_<true, F, S>
      {
         using type = F;
      };

      template<typename F, typename S>
      struct Select_impl_<false, F, S>
      {
         using type = S;
      };

      template<bool c, typename F, typename S>
      using Select_t = typename Select_impl_<c, F, S>::type;

      template <typename FirstT, typename SecondT, template<typename, typename> typename LessThanTypeComparatorT>
      struct Sort<TypeList<FirstT, SecondT>, LessThanTypeComparatorT>
      {
         using type = Select_t< LessThanTypeComparatorT<FirstT, SecondT>::value, TypeList<FirstT, SecondT>, TypeList<SecondT, FirstT> >;
      };

      template <typename FirstT, template<typename, typename> typename LessThanTypeComparatorT>
      struct Sort<TypeList<FirstT>, LessThanTypeComparatorT>
      {
         using type = TypeList<FirstT>;
      };

      template <template<typename, typename> typename LessThanTypeComparatorT>
      struct Sort<TypeList<>, LessThanTypeComparatorT>
      {
         using type = TypeList<>;
      };
   }

   template <typename TypeListT, template<typename, typename> typename LessThanTypeComparatorT>
   using Sort_t = typename detail::Sort<TypeListT, LessThanTypeComparatorT>::type;

   ////////////////////////////////////////////////////////
}
