#ifndef Dns_h__
#define Dns_h__

#include <string>
#include <array>
#include <vector>
#include <ostream>
#include <algorithm> // std::copy
#include <boost/asio/buffer.hpp>

#include "Header.h"

#include "bad_name.h"
#include "bad_data_stream.h"
#include "bad_ptr_offset.h"

namespace DnsProtocol
{

   struct PtrOffset2LabelInverter_t
   {
      virtual std::string operator()(uint16_t ptr_offset) = 0;
      // virtual ptr_offset operator()(const std::string& name) = 0;
   };

   struct LabelList_t
   {
      public:
         LabelList_t()
         {
            Set(std::string());
         }

         explicit LabelList_t(PtrOffset2LabelInverter_t* PO2LInvt)
            : m_PO2LInvt(PO2LInvt)
         {
            Set(std::string());
         }

         template<class Iter>
         void Load(Iter& begin, Iter end)
         {
            decltype(m_store) t_store;

            t_store.clear();
            t_store.reserve(256);

            uint8_t rem_labelchars = 0;
            bool term_found = false;
            bool ptr_found = false;

            for(; begin != end && !term_found; ++begin)
            {
               auto x = *begin;

               if(t_store.size() + 2 > 256)
                  throw bad_data_stream("length too long", 1);

               t_store.push_back(static_cast<uint8_t>(x));

               if(ptr_found)
               {
                  term_found = true;
               }
               else if(rem_labelchars == 0)
               {
                  uint8_t cx = static_cast<uint8_t>(x); // usually is the size of label, or null, or ptr_offset byte

                  if(cx == 0)
                  {
                     term_found = true;
                  }
                  else if(cx > 63)
                  {
                     if((cx & 0xC0) == 0xC0)
                        ptr_found = true;
                     else
                        throw bad_data_stream("length too long", 2);
                  }
                  else
                  {
                     rem_labelchars = cx;
                  }
               }
               else
               {
                  --rem_labelchars;
               }
            }

            if(!term_found)
               throw bad_data_stream("truncated", 2);

            swap(m_store, t_store);
         }

         LabelList_t& Set(const std::string& qname, uint16_t ptr_offset = 0)
         {
            if(ptr_offset > 0x3FFF)
               throw bad_ptr_offset("offset too long", 1);

            auto begin = qname.begin();
            auto end = qname.end();
            auto term_space = ptr_offset > 0 ? 2 : 1;

            decltype(m_store) t_store;

            t_store.clear();
            t_store.reserve(std::min(static_cast<int>(std::distance(begin, end) + term_space), 256));

            while(true)
            {
               auto pos = std::find(begin, end, '.');

               auto sz = pos - begin;

               if(sz > 63)
                  throw bad_name("length too long", 1);

               if(t_store.size() + sz + term_space >= 256)
                  throw bad_name("length too long", 2);

               if(sz == 0) // we seem to have hit the end
               {
                  if(begin != end)
                     throw bad_name("wrong format", 1);
                  else
                     break;
               }
               else
               {
                  t_store.push_back(sz); // non zero size

                  std::copy(begin, pos, std::back_inserter(t_store));

                  begin = (pos == end) ? pos : (pos + 1);

                  if(begin == end)
                     break;
               }
            }

            {
               // put the null terminator or the end ptr

               if(t_store.size() + term_space >= 256)
                  throw bad_name("length too long", 3);

               if(ptr_offset > 0)
               {
                  t_store.push_back(static_cast<uint8_t>(ptr_offset >> 8) | 0xC0);
                  t_store.push_back(static_cast<uint8_t>(ptr_offset & 0xFF));
               }
               else
               {
                  t_store.push_back(0);
               }
            }

            swap(m_store, t_store);

            return *this;
         }

         std::string Get1(uint16_t start_offset = 0) const
         {
            auto&& xx = Get(start_offset);

            return xx.first + (*m_PO2LInvt)(xx.second);
         }

         std::pair<std::string, uint16_t> Get(uint16_t start_offset = 0) const
         {
            std::string str;

            uint16_t ptr_offset = 0;
            uint8_t rem_labelchars = 0;

            for(auto x : m_store)
            {
               if(ptr_offset)
               {
                  ptr_offset |= static_cast<uint16_t>(x); // accumulate the second byte into ptr_offset LSB
               }
               else if(rem_labelchars == 0)
               {
                  uint8_t cx = static_cast<uint8_t>(x);

                  if((cx & 0xC0) == 0xC0) // found ptr_offset (first byte)
                  {
                     ptr_offset = static_cast<uint16_t>(x) << 8; // accumulate the first byte into ptr_offset MSB
                  }
                  else if(cx != 0)        // found non-zero label
                  {
                     rem_labelchars = cx;

                     if(!str.empty())
                        if(start_offset <= 0)
                           str += ".";
                  }
               }
               else
               {
                  --rem_labelchars;

                  if(start_offset <= 0)
                     str += static_cast<unsigned char>(x); // label char
               }

               if(start_offset > 0)
                  --start_offset;
            }

            return std::make_pair(str, ptr_offset & 0x3FFF);
         }

         void Save(std::vector<boost::asio::const_buffer>& buf) const
         {
            buf.push_back(boost::asio::const_buffer{&m_store[0], m_store.size()});
         }

         void Save(std::vector<uint8_t>& buf) const
         {
            std::copy(m_store.begin(), m_store.end(), std::back_inserter(buf));
         }

         auto Save() const
         {
            std::vector<uint8_t> buf;
            Save(buf);
            return buf;
         }

         friend std::ostream& operator<<(std::ostream& os, const LabelList_t& rhs)
         {
            auto&& res = rhs.Get();

            os << "[" << res.first << "]";

            if(res.second)
               os << "->[" << res.second << "]";

            return os;
         }

         uint16_t Size() const
         {
            return m_store.size();
         }

      private:
         std::vector<uint8_t> m_store;
         PtrOffset2LabelInverter_t* m_PO2LInvt;
   };

   struct Question_t
   {
      public:
         Question_t()
         {
         }

         explicit Question_t(PtrOffset2LabelInverter_t* PO2LInvt)
            : m_qname(PO2LInvt)
         {
         }

         Question_t& QName(const std::string& qname)
         {
            m_qname.Set(qname);

            return *this;
         }

         auto QName() const
         {
            return m_qname.Get();
         }

         Question_t& QType(uint16_t v)
         {
            m_store[0] = (v >> 8) & 0xFF;
            m_store[1] = (v >> 0) & 0xFF;

            return *this;
         }

         uint16_t QType() const
         {
            return (uint16_t(m_store[0]) << 8) |
                   (uint16_t(m_store[1]) << 0);
         }

         Question_t& QClass(uint16_t v)
         {
            m_store[2] = (v >> 8) & 0xFF;
            m_store[3] = (v >> 0) & 0xFF;

            return *this;
         }

         uint16_t QClass() const
         {
            return (uint16_t(m_store[2]) << 8) |
                   (uint16_t(m_store[3]) << 0);
         }

         void Save(std::vector<boost::asio::const_buffer>& buf) const
         {
            m_qname.Save(buf);
            buf.push_back(boost::asio::const_buffer{&m_store[0], m_store.size()});
         }

         void Save(std::vector<uint8_t>& buf) const
         {
            m_qname.Save(buf);
            std::copy(m_store.begin(), m_store.end(), std::back_inserter(buf));
         }

         auto Save() const
         {
            std::vector<uint8_t> buf;
            Save(buf);
            return buf;
         }

         template<class Iter>
         void Load(Iter& begin, Iter end)
         {
            m_qname.Load(begin, end);

            if(std::distance(begin, end) < m_store.size())
               throw bad_data_stream("truncated", 3);

            std::copy(begin, begin + m_store.size(), m_store.begin());

            begin += m_store.size();
         }

         friend std::ostream& operator<<(std::ostream& os, const Question_t& rhs)
         {
            return os << "{ QName=" << rhs.m_qname << ", QType=" << rhs.QType() << ", QClass=" << rhs.QClass() << " }";
         }

         uint16_t Size() const
         {
            return m_qname.Size() + m_store.size();
         }

      private:
         LabelList_t m_qname;
         std::array<uint8_t, 4> m_store;
   };

   struct ResourceRecord_t
   {
      public:
         ResourceRecord_t()
         {
         }

         explicit ResourceRecord_t(PtrOffset2LabelInverter_t* PO2LInvt)
            : m_rrname(PO2LInvt)
         {
         }

         ResourceRecord_t& RRName(const std::string& v)
         {
            m_rrname.Set(v);

            return *this;
         }

         auto RRName() const
         {
            return m_rrname.Get();
         }

         ResourceRecord_t& Type(uint16_t v)
         {
            m_store[0] = (v >> 8) & 0xFF;
            m_store[1] = (v >> 0) & 0xFF;

            return *this;
         }

         uint16_t Type() const
         {
            return (uint16_t(m_store[0]) << 8)
                   | (uint16_t(m_store[1]) << 0);
         }

         ResourceRecord_t& Class(uint16_t v)
         {
            m_store[2] = (v >> 8) & 0xFF;
            m_store[3] = (v >> 0) & 0xFF;

            return *this;
         }

         uint16_t Class() const
         {
            return (uint16_t(m_store[2]) << 8)
                   | (uint16_t(m_store[3]) << 0);
         }

         ResourceRecord_t& TTL(uint32_t v)
         {
            m_store[4] = (v >> 24) & 0xFF;
            m_store[5] = (v >> 16) & 0xFF;
            m_store[6] = (v >> 8) & 0xFF;
            m_store[7] = (v >> 0) & 0xFF;

            return *this;
         }

         uint32_t TTL() const
         {
            return (uint32_t(m_store[4]) << 24)
                   | (uint32_t(m_store[5]) << 16)
                   | (uint32_t(m_store[6]) << 8)
                   | (uint32_t(m_store[7]) << 0);
         }

         uint16_t RDLength() const
         {
            return (uint16_t(m_store[8]) << 8)
                   | (uint16_t(m_store[9]) << 0);
         }

         ResourceRecord_t& RData(std::vector<uint8_t> data)
         {
            if(data.size() > 0xFFFF)
               throw bad_data_stream("length too long", 3);

            RDLength(data.size());

            m_rdata = data;

            return *this;
         }

         std::vector<uint8_t> RData() const
         {
            return m_rdata;
         }

         void Save(std::vector<boost::asio::const_buffer>& buf) const
         {
            m_rrname.Save(buf);
            buf.push_back(boost::asio::const_buffer{&m_store[0], m_store.size()});
            buf.push_back(boost::asio::const_buffer{&m_rdata[0], m_rdata.size()});
         }

         void Save(std::vector<uint8_t>& buf) const
         {
            m_rrname.Save(buf);
            std::copy(m_store.begin(), m_store.end(), std::back_inserter(buf));
            std::copy(m_rdata.begin(), m_rdata.end(), std::back_inserter(buf));
         }

         auto Save() const
         {
            std::vector<uint8_t> buf;
            Save(buf);
            return buf;
         }

         template<class Iter>
         void Load(Iter& begin, Iter end)
         {
            m_rrname.Load(begin, end);

            if(std::distance(begin, end) < m_store.size())
               throw bad_data_stream("truncated", 4);

            std::copy(begin, begin + m_store.size(), m_store.begin());

            begin += m_store.size();

            m_rdata.resize(RDLength());

            if(std::distance(begin, end) < m_rdata.size())
               throw bad_data_stream("truncated", 5);

            std::copy(begin, begin + RDLength(), m_rdata.size());

            begin += m_rdata.size();
         }

         friend std::ostream& operator<<(std::ostream& os, const ResourceRecord_t& rhs)
         {
            return os << "{ RRName=" << rhs.m_rrname << ", Type=" << rhs.Type() << ", Class=" << rhs.Class() << ", TTL=" << rhs.TTL() << ", RDLength=" << rhs.RDLength() << " }";
         }

         uint16_t Size() const
         {
            return m_rrname.Size() + m_store.size() + m_rdata.size();
         }

      private:
         ResourceRecord_t& RDLength(uint16_t v)
         {
            m_store[8] = (v >> 8) & 0xFF;
            m_store[9] = (v >> 0) & 0xFF;

            return *this;
         }

      private:
         LabelList_t m_rrname;
         std::array<uint8_t, 10> m_store;
         std::vector<uint8_t> m_rdata;
   };

   struct Dns_t
   {
      public:
         Dns_t()
            : m_PO2LInvt(this)
            , m_Header( m_store )
         {
         }

         const Header_t& Header() const
         {
            return m_Header;
         }

         Header_t& Header()
         {
            return m_Header;
         }

         Question_t& Question(uint16_t x)
         {
            m_Question.resize(m_Header.QdCount());

            return m_Question.at(x);
         }

         ResourceRecord_t& Answer(uint16_t x)
         {
            m_Answer.resize(m_Header.AnCount());

            return m_Answer.at(x);
         }

         ResourceRecord_t& Authority(uint16_t x)
         {
            m_Authority.resize(m_Header.NsCount());

            return m_Authority.at(x);
         }

         ResourceRecord_t& Additional(uint16_t x)
         {
            m_Additional.resize(m_Header.ArCount());

            return m_Additional.at(x);
         }

         uint16_t Size() const
         {
            uint16_t sz = m_Header.Size();
            for(auto&& qn : m_Question)   sz += qn.Size();
            for(auto&& an : m_Answer)     sz += an.Size();
            for(auto&& au : m_Authority)  sz += au.Size();
            for(auto&& ad : m_Additional) sz += ad.Size();

            return sz;
         }

      private:
         /*
         uint16_t FindOffset(const std::string& label)
         {
            uint16_t finalOffset = m_Header.Size();

            for(auto&& qn : m_Question)
            {
               uint16_t off = qn.OffsetOf(label);

               if(off != -1)
               {
                  return finalOffset + off;
               }
               else
               {
                  finalOffset += m_Question.Size();
               }
            }

            return 0; // anything less then 12 can't be a valid offset
         }

         uint16_t FindOffset(const std::string& label)
         {
            uint16_t finalOffset = m_Header.Size();

            for(auto&& qn : m_Question)
            {
               uint16_t off = qn.OffsetOf(label);

               if(off != -1)
               {
                  return finalOffset + off;
               }
               else
               {
                  finalOffset += m_Question.Size();
               }
            }

            return 0; // anything less then 12 can't be a valid offset
         }
         */

      private:
         struct PO2LInvt_t : PtrOffset2LabelInverter_t
         {
            PO2LInvt_t(Dns_t* that)
               : m_DNS(that)
            {
            }

            std::string operator()(uint16_t ptr_offset) override
            {
               return "haha";
               // return m_DNS->LabelAt(ptr_offset);
            }

            /*
            ptr_offset operator()(const std::string& name) override
            {
               return m_DNS->OffsetFor(ptr_offset);
            }
            */

            Dns_t* m_DNS;

         };
         
      private:
         std::vector<uint8_t> m_store;
         PO2LInvt_t m_PO2LInvt;
         std::vector<LabelList_t> m_OtherLabels;

      private:
         Header_t m_Header;
         std::vector<Question_t> m_Question;
         std::vector<ResourceRecord_t> m_Answer;
         std::vector<ResourceRecord_t> m_Authority;
         std::vector<ResourceRecord_t> m_Additional;
   };
};

#endif
