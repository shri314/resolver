#pragma once

#include "dns/rr_type.h"
#include "dns/rr_class.h"

#include "dns/detail/name_offset_tracker.h"
#include "dns/detail/label_list.h"
#include "dns/detail/label_list/load_from.h"
#include "dns/detail/label_list/save_to.h"

#include "dns/record/rec_a.h"
#include "dns/record/rec_mx.h"
#include "dns/record/rec_ptr.h"
#include "dns/record/rec_ns.h"
#include "dns/record/rec_txt.h"
#include "dns/record/rec_cname.h"
#include "dns/record/rec_soa.h"

#include "util/oct_dump.h"

#include <boost/any.hpp>
#include <ostream>
#include <string>
#include <limits>

namespace dns
{
   class answer_t
   {
      public:
         void Name(const std::string& name)
         {
            m_name = name;
         }

         std::string Name() const
         {
            return m_name;
         }

         void Type(rr_type_t v)
         {
            m_type = v;
         }

         rr_type_t Type() const
         {
            return m_type;
         }

         void Class(rr_class_t v)
         {
            m_class = v;
         }

         rr_class_t Class() const
         {
            return m_class;
         }

         void TTL(uint32_t v)
         {
            m_TTL = v;
         }

         uint32_t TTL() const
         {
            return m_TTL;
         }

         template<class RecordT>
         RecordT Data() const
         {
            return boost::any_cast<RecordT>(m_rec);
         }

         template<class RecordT>
         void Data(RecordT&& v)
         {
            m_rec = std::forward<RecordT>(v);
         }

         friend std::ostream& operator<<(std::ostream& os, const answer_t& rhs)
         {
            os << "{ Name=" << rhs.Name() << ", Type=" << rhs.Type() << ", Class=" << rhs.Class() << ", TTL=" << rhs.TTL() << ", REC=";

            switch(rhs.Type())
            {
               case rr_type_t::rec_a:
                  os << rhs.Data<dns::rec_a_t>();
                  break;

               case rr_type_t::rec_mx:
                  os << rhs.Data<dns::rec_mx_t>();
                  break;

               case rr_type_t::rec_ptr:
                  os << rhs.Data<dns::rec_ptr_t>();
                  break;

               case rr_type_t::rec_ns:
                  os << rhs.Data<dns::rec_ns_t>();
                  break;

               case rr_type_t::rec_txt:
                  os << rhs.Data<dns::rec_txt_t>();
                  break;

               case rr_type_t::rec_soa:
                  os << rhs.Data<dns::rec_soa_t>();
                  break;

               case rr_type_t::rec_cname:
                  os << rhs.Data<dns::rec_cname_t>();
                  break;

               default:
                  os << util::oct_dump(rhs.Data<std::string>());
            }

            os << " }";
            return os;
         }

         friend bool operator==(const answer_t& lhs, const answer_t& rhs)
         {
            if(lhs.Name() == rhs.Name() &&
                  lhs.Type() == rhs.Type() &&
                  lhs.Class() == rhs.Class() &&
                  lhs.TTL() == rhs.TTL()
              )
            {
               switch(rhs.Type())
               {
                  case rr_type_t::rec_a:
                     return lhs.Data<dns::rec_a_t>() == rhs.Data<dns::rec_a_t>();

                  case rr_type_t::rec_mx:
                     return lhs.Data<dns::rec_mx_t>() == rhs.Data<dns::rec_mx_t>();

                  case rr_type_t::rec_ptr:
                     return lhs.Data<dns::rec_ptr_t>() == rhs.Data<dns::rec_ptr_t>();

                  case rr_type_t::rec_ns:
                     return lhs.Data<dns::rec_ns_t>() == rhs.Data<dns::rec_ns_t>();

                  case rr_type_t::rec_txt:
                     return lhs.Data<dns::rec_txt_t>() == rhs.Data<dns::rec_txt_t>();

                  case rr_type_t::rec_soa:
                     return lhs.Data<dns::rec_soa_t>() == rhs.Data<dns::rec_soa_t>();

                  case rr_type_t::rec_cname:
                     return lhs.Data<dns::rec_cname_t>() == rhs.Data<dns::rec_cname_t>();

                  default:
                     return false;
               }
            }

            return false;
         }

      private:
         std::string m_name;
         rr_type_t m_type = rr_type_t::rec_a;
         rr_class_t m_class = rr_class_t::internet;
         int32_t m_TTL = 0;
         boost::any m_rec;
   };

   inline void save_to(name_offset_tracker_t& tr, const answer_t& r)
   {
      save_to(tr, label_list_t{r.Name()});
      save_to(tr, static_cast<uint16_t>(r.Type()));
      save_to(tr, static_cast<uint16_t>(r.Class()));
      save_to(tr, r.TTL());

      uint16_t offset = tr.current_offset();
      save_to(tr, static_cast<uint16_t>(0));

      switch(r.Type())
      {
         case rr_type_t::rec_a:
            save_to(tr, r.Data<rec_a_t>());
            break;

         case rr_type_t::rec_mx:
            save_to(tr, r.Data<rec_mx_t>());
            break;

         case rr_type_t::rec_ptr:
            save_to(tr, r.Data<rec_ptr_t>());
            break;

         case rr_type_t::rec_ns:
            save_to(tr, r.Data<rec_ns_t>());
            break;

         case rr_type_t::rec_txt:
            save_to(tr, r.Data<rec_txt_t>());
            break;

         case rr_type_t::rec_soa:
            save_to(tr, r.Data<rec_soa_t>());
            break;

         case rr_type_t::rec_cname:
            save_to(tr, r.Data<rec_cname_t>());
            break;

         default:
            for(auto && c : r.Data<std::string>())
               save_to(tr, static_cast<uint8_t>(c));
            break;
      }

      auto&& ptr = tr.slice(offset, offset + sizeof(offset));
      save_to(*ptr, static_cast<uint16_t>(tr.current_offset() - sizeof(offset) - offset));
   }

   template<>
   struct LoadImpl<answer_t>
   {
      template<class InputIterator>
      static answer_t impl(name_offset_tracker_t& tr, InputIterator& ii, InputIterator end)
      {
         answer_t r{};

         {
            r.Name(load_from<label_list_t>(tr, ii, end).Name());
            r.Type(static_cast<rr_type_t>(load_from<uint16_t>(tr, ii, end)));
            r.Class(static_cast<rr_class_t>(load_from<uint16_t>(tr, ii, end)));
            r.TTL(load_from<uint32_t>(tr, ii, end));
         }

         {
            uint16_t record_length = load_from<uint16_t>(tr, ii, end);
            uint16_t record_offset = tr.current_offset();

            for(uint16_t i = 0; i < record_length; ++i)
               load_from<uint8_t>(tr, ii, end);

            if(auto && rec_tr = tr.slice(record_offset, record_offset + record_length))
            {
               auto&& rec_b = rec_tr->cbegin();
               auto&& rec_e = rec_tr->cend();

               switch(r.Type())
               {
                  case rr_type_t::rec_a:
                     r.Data(load_from<rec_a_t>(*rec_tr, rec_b, rec_e));
                     break;

                  case rr_type_t::rec_mx:
                     r.Data(load_from<rec_mx_t>(*rec_tr, rec_b, rec_e));
                     break;

                  case rr_type_t::rec_ptr:
                     r.Data(load_from<rec_ptr_t>(*rec_tr, rec_b, rec_e));
                     break;

                  case rr_type_t::rec_ns:
                     r.Data(load_from<rec_ns_t>(*rec_tr, rec_b, rec_e));
                     break;

                  case rr_type_t::rec_txt:
                     r.Data(load_from<rec_txt_t>(*rec_tr, rec_b, rec_e));
                     break;

                  case rr_type_t::rec_soa:
                     r.Data(load_from<rec_soa_t>(*rec_tr, rec_b, rec_e));
                     break;

                  case rr_type_t::rec_cname:
                     r.Data(load_from<rec_cname_t>(*rec_tr, rec_b, rec_e));
                     break;

                  default:
                  {
                     auto&& raw_data = std::string{};

                     raw_data.resize(record_length);
                     for(uint16_t i = 0; i < record_length; ++i)
                        raw_data[i] = load_from<uint8_t>(tr, rec_b, rec_e);

                     r.Data(raw_data);
                  }
                  break;
               }
            }
            else
               throw dns::exception::bad_data_stream("bad record", 5);
         }

         return r;
      }
   };
}
