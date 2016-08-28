#pragma once

#include <ostream>
#include <string>

namespace dns
{
   class rec_txt_t
   {
      public:
         rec_txt_t(std::string text)
            : m_text(std::move(text))
         {
         }

         rec_txt_t()
            : rec_txt_t{{}}
         {
         }

         void Text(std::string v)
         {
            m_text = std::move(v);
         }

         std::string Text() const
         {
            return m_text;
         }

         friend std::ostream& operator<<(std::ostream& os, const rec_txt_t& rhs)
         {
            return os << "[" << rhs.Text() << "]";
         }

         friend bool operator==(const rec_txt_t& lhs, const rec_txt_t& rhs)
         {
            return lhs.Text() == rhs.Text();
         }

         static const rr_type_t m_type = dns::rr_type_t::rec_txt;

      private:
         std::string m_text;
   };

   inline void save_to(name_offset_tracker_t& tr, const rec_txt_t& r)
   {
      auto&& text = r.Text();
      auto&& begin = text.cbegin();
      auto&& end = text.cend();

      while( auto&& sz = static_cast<uint8_t>((end - begin > 255) ? 255 : (end - begin)) )
      {
         save_to(tr, static_cast<uint8_t>(sz));

         for(; sz > 0; ++begin, --sz)
            save_to(tr, static_cast<uint8_t>(*begin));
      }
   }

   template<>
   struct LoadImpl<rec_txt_t>
   {
      template<class InputIterator>
      static rec_txt_t impl(name_offset_tracker_t& tr, InputIterator& ii, InputIterator end)
      {
         rec_txt_t r{};

         std::string buff;

         while( ii != end )
         {
            uint8_t sz = load_from<uint8_t>(tr, ii, end);
            buff.reserve( buff.size() + sz );

            for(uint8_t i = 0; i < sz; ++i)
               buff.push_back( load_from<uint8_t>(tr, ii, end) );
         }

         r.Text(buff);

         return r;
      }
   };
}
