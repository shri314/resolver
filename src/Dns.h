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

   struct Header
   {
      public:
         Header& ID(uint16_t v)
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

         Header& QR_Flag(bool v)
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

         Header& OpCode(uint16_t v)
         {
            m_store[2] |= (v & 0xF) << 3;
            m_store[2] &= ~((~v & 0xF) << 3);

            return *this;
         }

         uint16_t OpCode() const
         {
            return (m_store[2] >> 3) & 0xF;
         }

         Header& AA_Flag(bool v)
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

         Header& TC_Flag(bool v)
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

         Header& RD_Flag(bool v)
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

         Header& RA_Flag(bool v)
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

         Header& ZCode(uint16_t v)
         {
            m_store[3] |= (v & 0x7) << 4;
            m_store[3] &= ~((~v & 0x7) << 4);

            return *this;
         }

         uint16_t ZCode()
         {
            return (m_store[3] >> 4) & 0x7;
         }

         Header& RCode(uint16_t v)
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

         Header& QdCount(uint16_t v)
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

         Header& AnCount(uint16_t v)
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

         Header& NsCount(uint16_t v)
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

         Header& ArCount(uint16_t v)
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

         auto Save(std::vector<boost::asio::const_buffer>& buf) const
         {
            buf.push_back(boost::asio::const_buffer{&m_store[0], m_store.size()});
         }

         auto Save(std::vector<uint8_t>& buf) const
         {
            std::copy(m_store.begin(), m_store.end(), std::back_inserter(buf));
         }

         auto Save() const
         {
            std::vector<uint8_t> buf;
            Save(buf);
            return buf;
         }

         Header()
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

         friend std::ostream& operator<<(std::ostream& os, const Header& rhs)
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

   struct QualifiedName
   {
      public:
         QualifiedName()
         {
            Set(std::string());
         }

         template<class Iter>
         void Load(Iter& begin, Iter end)
         {
            decltype(m_store) t_store;

            t_store.clear();
            t_store.reserve(255);

            bool nullfound = false;
            unsigned c = 0;
            for(; begin != end && !nullfound; ++begin)
            {
               auto x = *begin;

               if(t_store.size() >= 255)
                  throw bad_data_stream("length too long", 1);

               t_store.push_back(static_cast<uint8_t>(x));

               if(c == 0)
               {
                  c = static_cast<unsigned>(x);

                  if(c == 0)
                  {
                     // c stayed 0 (which means its a null label)
                     nullfound = true;
                  }
                  else if(c < 0 || c > 63)
                  {
                     throw bad_data_stream("length too long", 2);
                  }
               }
               else
               {
                  --c;
               }
            }

            if(!nullfound)
               throw bad_data_stream("truncated", 2);

            swap(m_store, t_store);
         }

         QualifiedName& Set(const std::string& qname)
         {
            auto begin = qname.begin();
            auto end = qname.end();

            decltype(m_store) t_store;

            t_store.clear();
            t_store.reserve(std::min(static_cast<int>(std::distance(begin, end) + 1), 255));

            while(true)
            {
               auto pos = std::find(begin, end, '.');

               auto sz = pos - begin;

               if(sz > 63)
               {
                  throw bad_name("length too long", 1);
               }

               if(t_store.size() + sz >= 255)
                  throw bad_name("length too long", 2);

               t_store.push_back(sz);

               if(sz == 0) // we seem to have hit the end
               {
                  if(begin != end)
                     throw bad_name("wrong format", 1);
                  else
                     break;
               }
               else
               {
                  std::copy(begin, pos, std::back_inserter(t_store));

                  begin = (pos == end) ? pos : (pos + 1);

                  if(begin == end)
                  {
                     if(t_store.size() >= 255)
                        throw bad_name("length too long", 3);

                     t_store.push_back(0);

                     break;
                  }
               }
            }

            swap(m_store, t_store);

            return *this;
         }

         std::string Get() const
         {
            std::string str;
            std::string sep;

            unsigned c = 0;
            for(auto x : m_store)
            {
               if(c == 0)
               {
                  c = static_cast<unsigned>(x);

                  if(c != 0)
                     str += sep;
               }
               else
               {
                  --c;

                  sep = ".";

                  str += static_cast<unsigned char>(x);
               }
            }

            return str;
         }

         auto Save(std::vector<boost::asio::const_buffer>& buf) const
         {
            buf.push_back(boost::asio::const_buffer{&m_store[0], m_store.size()});
         }

         auto Save(std::vector<uint8_t>& buf) const
         {
            std::copy(m_store.begin(), m_store.end(), std::back_inserter(buf));
         }

         auto Save() const
         {
            std::vector<uint8_t> buf;
            Save(buf);
            return buf;
         }

         friend std::ostream& operator<<(std::ostream& os, const QualifiedName& rhs)
         {
            return os << rhs.Get();
         }

      private:
         std::vector<uint8_t> m_store;
   };

   struct Question
   {
      public:
         Question()
         {
         }

         Question& QName(const std::string& qname)
         {
            m_qname.Set(qname);

            return *this;
         }

         std::string QName() const
         {
            return m_qname.Get();
         }

         Question& QType(uint16_t v)
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

         Question& QClass(uint16_t v)
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

         auto Save(std::vector<boost::asio::const_buffer>& buf) const
         {
            m_qname.Save(buf);
            buf.push_back(boost::asio::const_buffer{&m_store[0], m_store.size()});
         }

         auto Save(std::vector<uint8_t>& buf) const
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

      private:
         QualifiedName m_qname;
         std::array<uint8_t, 4> m_store;
   };
};

#endif
