#pragma once

namespace util
{
   ////////////////////////////////////////////////////////

   template <typename KeyT, KeyT Key, typename TypeT>
   struct TypeMap;

   ////////////////////////////////////////////////////////

   namespace detail
   {
      template<typename TypeMapT>
      struct ExtractKey;

      template<typename KeyT, KeyT Key, typename TypeT>
      struct ExtractKey< TypeMap<KeyT, Key, TypeT> >
      {
         constexpr static const auto value = Key;
      };
   }

   template<typename TypeMapT>
   constexpr auto ExtractKey_v = detail::ExtractKey<TypeMapT>::value;

   ////////////////////////////////////////////////////////

   namespace detail
   {
      template<typename TypeMapT>
      struct ExtractType;

      template<typename KeyT, KeyT Key, typename TypeT>
      struct ExtractType< TypeMap<KeyT, Key, TypeT> >
      {
         using type = TypeT;
      };
   }

   template<typename TypeMapT>
   using ExtractType_t = typename detail::ExtractType<TypeMapT>::type;

   ////////////////////////////////////////////////////////
}
