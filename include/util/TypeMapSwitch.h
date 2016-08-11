#pragma once

#include "TypeList.h"
#include "TypeMap.h"

#include <utility>

namespace util
{
   ////////////////////////////////////////////////////////

   namespace detail
   {
      template<typename TypeMapListT>
      struct TypeMapListSwitch
      {
         private:
            template<typename LeftTypeMapT, typename RightTypeMapT>
            struct TypeMapTLessComparator
            {
               constexpr static auto value = static_cast<int64_t>(ExtractKey_v<LeftTypeMapT>) < static_cast<int64_t>(ExtractKey_v<RightTypeMapT>);
            };

            using SortedTypeMapListT = Sort_t<TypeMapListT, TypeMapTLessComparator>;

            constexpr static auto mid_pos = Size_v<SortedTypeMapListT> / 2;

            using TypeMapT = Access_t<SortedTypeMapListT, mid_pos>;
            using LeftTypeMapListSwitchT  = TypeMapListSwitch< Slice_t<SortedTypeMapListT, 0, mid_pos> >;
            using RightTypeMapListSwitchT = TypeMapListSwitch < Slice_t < SortedTypeMapListT, mid_pos + 1 > >;

         public:
            template<template<typename> typename WorkFuncT, typename KeyT, typename... Args>
            static void dispatch(KeyT&& key, Args&& ... args)
            {
               if(static_cast<int64_t>(key) == static_cast<int64_t>(ExtractKey_v<TypeMapT>))
               {
                  WorkFuncT< ExtractType_t<TypeMapT> > wf{};

                  wf(std::forward<Args>(args)...);
               }
               else if(static_cast<int64_t>(key) < static_cast<int64_t>(ExtractKey_v<TypeMapT>))
               {
                  LeftTypeMapListSwitchT::template dispatch<WorkFuncT>(key, std::forward<Args>(args)...);
               }
               else
               {
                  RightTypeMapListSwitchT::template dispatch<WorkFuncT>(key, std::forward<Args>(args)...);
               }
            }
      };

      template<>
      struct TypeMapListSwitch< TypeList<> >
      {
         public:
            template<template<typename> typename WorkFuncT, typename KeyT, typename... Args>
            static void dispatch(KeyT&& key, Args&& ... args)
            {
               WorkFuncT<void> wf{};                // default case

               wf(std::forward<Args>(args)...);
            }
      };
   }

   template<typename... TypeMapT>
   using TypeMapSwitch_t = detail::TypeMapListSwitch< TypeList<TypeMapT...> >;

   ////////////////////////////////////////////////////////
}
