#ifndef Dns_h__
#define Dns_h__

#include <string>
#include <array>
#include <vector>
#include <ostream>
#include <algorithm> // std::copy
#include <boost/asio/buffer.hpp>

namespace DnsProtocol
{
   struct bad_name : public std::exception
   {
      public:
         bad_name(const char* const str, int code)
            : m_str(str)
            , m_code(code)
         {
         }

         bad_name(bad_name& rhs)
            : m_str(rhs.m_str)
            , m_code(rhs.m_code)
         {
         }

         bad_name(bad_name&& rhs)
            : m_str(rhs.m_str)
            , m_code(rhs.m_code)
         {
         }

         int code() const noexcept { return m_code; }

         const char* what() const noexcept { return m_str; }

         void operator=(const bad_name&) = delete;
         void operator=(bad_name&&) = delete;

      private:
         const char* const m_str;
         int m_code;
   };

   struct bad_ptr_offset : public std::exception
   {
      public:
         bad_ptr_offset(const char* const str, int code)
            : m_str(str)
            , m_code(code)
         {
         }

         bad_ptr_offset(bad_ptr_offset& rhs)
            : m_str(rhs.m_str)
            , m_code(rhs.m_code)
         {
         }

         bad_ptr_offset(bad_ptr_offset&& rhs)
            : m_str(rhs.m_str)
            , m_code(rhs.m_code)
         {
         }

         int code() const noexcept { return m_code; }

         const char* what() const noexcept { return m_str; }

         void operator=(const bad_ptr_offset&) = delete;
         void operator=(bad_ptr_offset&&) = delete;

      private:
         const char* const m_str;
         int m_code;
   };

   struct bad_data_stream : public std::exception
   {
      public:
         bad_data_stream(const char* const str, int code)
            : m_str(str)
            , m_code(code)
         {
         }

         bad_data_stream(bad_data_stream& rhs)
            : m_str(rhs.m_str)
            , m_code(rhs.m_code)
         {
         }

         bad_data_stream(bad_data_stream&& rhs)
            : m_str(rhs.m_str)
            , m_code(rhs.m_code)
         {
         }

         int code() const noexcept { return m_code; }

         const char* what() const noexcept { return m_str; }

         void operator=(const bad_data_stream&) = delete;
         void operator=(bad_data_stream&&) = delete;

      private:
         const char* const m_str;
         int m_code;
   };

   struct Header_t
   {
      public:
         Header_t& ID(uint16_t v)
         {
            m_store[0] = (v >> 8) & 0xFF;
            m_store[1] = (v >> 0) & 0xFF;

            return *this;
         }

         uint16_t ID() const
         {
            return (uint16_t(m_store[0]) << 8)
                   | (uint16_t(m_store[1]) << 0);
         }

         //////////////

         Header_t& QR_Flag(bool v)
         {
            if(v)
               m_store[2] |= 0x80;
            else
               m_store[2] &= ~0x80;

            return *this;
         }

         bool QR_Flag() const
         {
            return (m_store[2] & 0x80) == 0x80;
         }

         Header_t& OpCode(uint16_t v)
         {
            m_store[2] |= (v & 0xF) << 3;
            m_store[2] &= ~((~v & 0xF) << 3);

            return *this;
         }

         uint16_t OpCode() const
         {
            return (m_store[2] >> 3) & 0xF;
         }

         Header_t& AA_Flag(bool v)
         {
            if(v)
               m_store[2] |= 0x04;
            else
               m_store[2] &= ~0x04;

            return *this;
         }

         bool AA_Flag() const
         {
            return (m_store[2] & 0x04) == 0x04;
         }

         Header_t& TC_Flag(bool v)
         {
            if(v)
               m_store[2] |= 0x02;
            else
               m_store[2] &= ~0x02;

            return *this;
         }

         bool TC_Flag() const
         {
            return (m_store[2] & 0x02) == 0x02;
         }

         Header_t& RD_Flag(bool v)
         {
            if(v)
               m_store[2] |= 0x01;
            else
               m_store[2] &= ~0x01;

            return *this;
         }

         bool RD_Flag() const
         {
            return m_store[2] & 0x01 == 0x01;
         }

         //////////////

         Header_t& RA_Flag(bool v)
         {
            if(v)
               m_store[3] |= 0x80;
            else
               m_store[3] &= ~0x80;

            return *this;
         }

         bool RA_Flag() const
         {
            return (m_store[3] & 0x80) == 0x80;
         }

         Header_t& ZCode(uint16_t v)
         {
            m_store[3] |= (v & 0x7) << 4;
            m_store[3] &= ~((~v & 0x7) << 4);

            return *this;
         }

         uint16_t ZCode()
         {
            return (m_store[3] >> 4) & 0x7;
         }

         Header_t& RCode(uint16_t v)
         {
            m_store[3] |= (v & 0xF);
            m_store[3] &= ~(~v & 0xF);

            return *this;
         }

         uint16_t RCode() const
         {
            return (m_store[3] & 0xF);
         }

         /////////////

         Header_t& QdCount(uint16_t v)
         {
            m_store[4] = (v >> 8) & 0xFF;
            m_store[5] = (v >> 0) & 0xFF;

            return *this;
         }

         uint16_t QdCount() const
         {
            return (uint16_t(m_store[4]) << 8)
                   | (uint16_t(m_store[5]) << 0);
         }

         Header_t& AnCount(uint16_t v)
         {
            m_store[6] = (v >> 8) & 0xFF;
            m_store[7] = (v >> 0) & 0xFF;

            return *this;
         }

         uint16_t AnCount() const
         {
            return (uint16_t(m_store[6]) << 8)
                   | (uint16_t(m_store[7]) << 0);
         }

         Header_t& NsCount(uint16_t v)
         {
            m_store[8] = (v >> 8) & 0xFF;
            m_store[9] = (v >> 0) & 0xFF;

            return *this;
         }

         uint16_t NsCount() const
         {
            return (uint16_t(m_store[8]) << 8)
                   | (uint16_t(m_store[9]) << 0);
         }

         Header_t& ArCount(uint16_t v)
         {
            m_store[10] = (v >> 8) & 0xFF;
            m_store[11] = (v >> 0) & 0xFF;

            return *this;
         }

         uint16_t ArCount() const
         {
            return (uint16_t(m_store[10]) << 8)
                   | (uint16_t(m_store[11]) << 0);
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

         Header_t()
         {
            ZCode(0);
         }

         template<class Iter>
         void Load(Iter& begin, Iter end)
         {
            if(std::distance(begin, end) < m_store.size())
               throw bad_data_stream("truncated", 1);

            std::copy(begin, begin + m_store.size(), m_store.begin());

            begin += m_store.size();
         }

         friend std::ostream& operator<<(std::ostream& os, const Header_t& rhs)
         {
            os << "{ ";
            os << "ID=" << rhs.ID() << ", ";
            {
               os << "Flags=[";
               std::string sep = "";
               for(auto F :
                     {
                        std::string(rhs.QR_Flag() ? "RES" : "QRY"),
                        std::string(rhs.AA_Flag() ? "AA" : ""),
                        std::string(rhs.TC_Flag() ? "TC" : ""),
                        std::string(rhs.RD_Flag() ? "RD" : ""),
                        std::string(rhs.RA_Flag() ? "RA" : "")
                     })
               {
                  if(!F.empty())
                  {
                     os << sep << F;
                     if(sep.empty())
                        sep = ",";
                  }
               }
               os << "], ";
            }
            os << "OpCode=" << rhs.OpCode() << ", ";
            os << "RCode=" << rhs.RCode() << ", ";

            os << "QdCount=" << rhs.QdCount() << ", ";
            os << "AnCount=" << rhs.AnCount() << ", ";
            os << "NsCount=" << rhs.NsCount() << ", ";
            os << "ArCount=" << rhs.ArCount() << " ";
            os << "}";

            return os;
         }

      private:
         std::array<uint8_t, 12> m_store;
   };

   struct LabelList_t
   {
      public:
         LabelList_t()
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

      private:
         std::vector<uint8_t> m_store;
   };

   struct Question_t
   {
      public:
         Question_t()
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

      private:
         Header_t m_Header;
         std::vector<Question_t> m_Question;
         std::vector<ResourceRecord_t> m_Answer;
         std::vector<ResourceRecord_t> m_Authority;
         std::vector<ResourceRecord_t> m_Additional;
   };
};

#endif
