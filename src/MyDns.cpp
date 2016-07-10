#include <string>
#include <iostream>
#include <boost/asio.hpp>

using namespace std::string_literals;

void handle_resolve_query(const boost::system::error_code& ec, boost::asio::ip::tcp::resolver::iterator iter)
{
   if(ec)
   {
      std::cout << ec.message() << "\n";
      return;
   }

   std::for_each(iter, boost::asio::ip::tcp::resolver::iterator{}, [](boost::asio::ip::tcp::endpoint endpoint)
   {
      std::cout << endpoint << "\n";
   });
}

void basic_io(int argc, char** argv)
{
   boost::asio::io_service io;
   boost::asio::ip::tcp::resolver r(io);

   for(int i = 1; i < argc; ++i)
   {
      r.async_resolve(
         boost::asio::ip::tcp::resolver::query(argv[i], "http"),
         handle_resolve_query
      );
   }

   io.run();
}

#include "raw_dump.h"

struct Dns_t
{
      struct Header_t
      {
         public:
            enum class OpCode_t : uint8_t
            {
               QUERY  = 0,
               IQUERY = 1,
               STATUS = 2,

               NOTIFY = 4,
               UPDATE = 5,
            };

            friend std::ostream& operator<<(std::ostream& os, Header_t::OpCode_t rhs)
            {
               switch(rhs)
               {
                  case OpCode_t::QUERY:  return os << "QUERY";
                  case OpCode_t::IQUERY: return os << "IQUERY";
                  case OpCode_t::STATUS: return os << "STATUS";
                  case OpCode_t::NOTIFY: return os << "NOTIFY";
                  case OpCode_t::UPDATE: return os << "UPDATE";
                  default: return os << static_cast<unsigned>(rhs);
               }
            }

            enum class RCode_t : uint8_t
            {
               NO_ERROR   = 0,
               FORM_ERR   = 1,
               SERV_FAIL  = 2,
               NX_DOMAIN  = 3,
               NOT_IMP    = 4,
               REFUSED    = 5,
               YX_DOMAIN  = 6,
               YX_RRSET   = 7,
               NX_RRSET   = 8,
               NOT_AUTH   = 9,

               BAD_VERS   = 16,
               BAD_SIG    = 17,
               BAD_KEY    = 18,
               BAD_TIME   = 19,
               BAD_MODE   = 20,
               BAD_NAME   = 21,
               BAD_ALG    = 22,
               BAD_TRUNC  = 23,
               BAD_COOKIE = 24,
            };

            friend std::ostream& operator<<(std::ostream& os, RCode_t rhs)
            {
               switch(rhs)
               {
                  case RCode_t::NO_ERROR:   return os << "NO_ERROR";
                  case RCode_t::FORM_ERR:   return os << "FORM_ERR";
                  case RCode_t::SERV_FAIL:  return os << "SERV_FAIL";
                  case RCode_t::NX_DOMAIN:  return os << "NX_DOMAIN";
                  case RCode_t::NOT_IMP:    return os << "NOT_IMP";
                  case RCode_t::REFUSED:    return os << "REFUSED";
                  case RCode_t::YX_DOMAIN:  return os << "YX_DOMAIN";
                  case RCode_t::YX_RRSET:   return os << "YX_RRSET";
                  case RCode_t::NX_RRSET:   return os << "NX_RRSET";
                  case RCode_t::NOT_AUTH:   return os << "NOT_AUTH";

                  case RCode_t::BAD_VERS:   return os << "BAD_VERS";
                  case RCode_t::BAD_SIG:    return os << "BAD_SIG";
                  case RCode_t::BAD_KEY:    return os << "BAD_KEY";
                  case RCode_t::BAD_TIME:   return os << "BAD_TIME";
                  case RCode_t::BAD_MODE:   return os << "BAD_MODE";
                  case RCode_t::BAD_NAME:   return os << "BAD_NAME";
                  case RCode_t::BAD_ALG:    return os << "BAD_ALG";
                  case RCode_t::BAD_TRUNC:  return os << "BAD_TRUNC";
                  case RCode_t::BAD_COOKIE: return os << "BAD_COOKIE";

                  default: return os << static_cast<unsigned>(rhs);
               }
            }

         public:
            template<class OutputIterator>
            void fill_into(OutputIterator o)
            {
               {
                  *o++ = static_cast<uint8_t>(m_ID >> 8) & 0xFF;
                  *o++ = static_cast<uint8_t>(m_ID >> 0) & 0xFF;
               }

               {
                  *o++ = (m_QR ? 0x80 : 0) |
                         ((static_cast<uint8_t>(m_OpCode) & 0xF) << 3) |
                         (m_AA ? 0x04 : 0) |
                         (m_TC ? 0x02 : 0) |
                         (m_RD ? 0x01 : 0);
               }

               {
                  *o++ = (m_RA ? 0x80 : 0) |
                         (m_Res1 ? 0x40 : 0) |
                         (m_AD ? 0x20 : 0) |
                         (m_CD ? 0x10 : 0) |
                         (static_cast<uint8_t>(m_OpCode) & 0xF);
               }

               {
                  *o++ = static_cast<uint8_t>(m_QdCount >> 8) & 0xFF;
                  *o++ = static_cast<uint8_t>(m_QdCount >> 0) & 0xFF;
               }

               {
                  *o++ = static_cast<uint8_t>(m_AnCount >> 8) & 0xFF;
                  *o++ = static_cast<uint8_t>(m_AnCount >> 0) & 0xFF;
               }

               {
                  *o++ = static_cast<uint8_t>(m_NsCount >> 8) & 0xFF;
                  *o++ = static_cast<uint8_t>(m_NsCount >> 0) & 0xFF;
               }

               {
                  *o++ = static_cast<uint8_t>(m_ArCount >> 8) & 0xFF;
                  *o++ = static_cast<uint8_t>(m_ArCount >> 0) & 0xFF;
               }
            }

            template<class InputIterator>
            void load_from(InputIterator i, InputIterator end)
            {
               {
                  if(i != end) m_ID = static_cast<uint16_t>(*i++) << 8;
                  if(i != end) m_ID |= static_cast<uint16_t>(*i++);
               }

               if(i != end)
               {
                  uint8_t v = static_cast<uint8_t>(*i++);

                  m_QR = (v & 0x80) == 0x80 ? true : false;
                  m_OpCode = static_cast<OpCode_t>((v >> 3) & 0xF);
                  m_AA = (v & 0x04) == 0x04 ? true : false;
                  m_TC = (v & 0x02) == 0x02 ? true : false;
                  m_RD = (v & 0x01) == 0x01 ? true : false;
               }

               if(i != end)
               {
                  uint8_t v = static_cast<uint8_t>(*i++);

                  m_RA = (v & 0x80) == 0x80 ? true : false;
                  m_Res1 = (v & 0x40) == 0x40 ? true : false;
                  m_Res1 = (v & 0x20) == 0x20 ? true : false;
                  m_Res1 = (v & 0x10) == 0x10 ? true : false;
                  m_RCode = static_cast<RCode_t>(v & 0xF);
               }

               {
                  if(i != end) m_QdCount = static_cast<uint16_t>(*i++) << 8;
                  if(i != end) m_QdCount |= static_cast<uint16_t>(*i++);
               }

               {
                  if(i != end) m_AnCount = static_cast<uint16_t>(*i++) << 8;
                  if(i != end) m_AnCount |= static_cast<uint16_t>(*i++);
               }

               {
                  if(i != end) m_NsCount = static_cast<uint16_t>(*i++) << 8;
                  if(i != end) m_NsCount |= static_cast<uint16_t>(*i++);
               }

               {
                  if(i != end) m_ArCount = static_cast<uint16_t>(*i++) << 8;
                  if(i != end) m_ArCount |= static_cast<uint16_t>(*i++);
               }
            }

            uint16_t ID() const
            {
               return m_ID;
            }

            void ID(uint16_t v)
            {
               m_ID = v;
            }

            bool QR_Flag() const
            {
               return m_QR;
            }

            void QR_Flag(bool v)
            {
               m_QR = v;
            }

            OpCode_t OpCode() const
            {
               return m_OpCode;
            }

            void OpCode(OpCode_t v)
            {
               m_OpCode = v;
            }

            bool AA_Flag() const
            {
               return m_AA;
            }

            void AA_Flag(bool v)
            {
               m_AA = v;
            }

            bool TC_Flag() const
            {
               return m_TC;
            }

            void TC_Flag(bool v)
            {
               m_TC = v;
            }

            bool RD_Flag() const
            {
               return m_RD;
            }

            void RD_Flag(bool v)
            {
               m_RD = v;
            }

            bool RA_Flag() const
            {
               return m_RA;
            }

            void RA_Flag(bool v)
            {
               m_RA = v;
            }

            bool Res1_Flag() const
            {
               return m_Res1;
            }

            void Res1_Flag(bool v)
            {
               m_Res1 = v;
            }

            bool AD_Flag() const
            {
               return m_AD;
            }

            void AD_Flag(bool v)
            {
               m_AD = v;
            }

            bool CD_Flag() const
            {
               return m_CD;
            }

            void CD_Flag(bool v)
            {
               m_CD = v;
            }

            RCode_t RCode() const
            {
               return m_RCode;
            }

            void RCode(RCode_t v)
            {
               m_RCode = v;
            }

            uint16_t QdCount() const
            {
               return m_QdCount;
            }

            void QdCount(uint16_t v)
            {
               m_QdCount = v;
            }

            uint16_t AnCount() const
            {
               return m_AnCount;
            }

            void AnCount(uint16_t v)
            {
               m_AnCount = v;
            }

            uint16_t NsCount() const
            {
               return m_NsCount;
            }

            void NsCount(uint16_t v)
            {
               m_NsCount = v;
            }

            uint16_t ArCount() const
            {
               return m_ArCount;
            }

            void ArCount(uint16_t v)
            {
               m_ArCount = v;
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
                           std::string(rhs.RA_Flag() ? "RA" : ""),
                           std::string(rhs.AD_Flag() ? "AD" : ""),
                           std::string(rhs.CD_Flag() ? "CD" : "")
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
            uint16_t m_ID = 0;

            bool m_QR = false;
            OpCode_t m_OpCode = OpCode_t::QUERY;
            bool m_AA = false;
            bool m_TC = false;
            bool m_RD = false;

            bool m_RA = false;
            bool m_Res1 = false;
            bool m_AD = false;
            bool m_CD = false;
            RCode_t m_RCode = RCode_t::NO_ERROR;

            uint16_t m_QdCount = 0;
            uint16_t m_AnCount = 0;
            uint16_t m_NsCount = 0;
            uint16_t m_ArCount = 0;
      };

      struct Question
      {
      };
};

void basic_dns(int argc, char** argv)
{
   boost::asio::io_service io;
   boost::asio::ip::tcp::endpoint endpoint(boost::asio::ip::address::from_string("8.8.8.8"), 53);
   boost::asio::ip::tcp::socket socket(io);
   std::vector<uint8_t> write_buffer;
   std::vector<uint8_t> recv_buffer;

   auto&& onReadResponse = [&](auto ec, auto sz_rx)
   {
      if(sz_rx <= 0 && !ec)
      {
         std::cout << "read failed - " << ec.message() << "\n";
      }
      else
      {
         std::cout << OctRep(std::string(recv_buffer.begin(), recv_buffer.begin() + sz_rx)) << "\n";

         Dns_t::Header_t h;
         h.load_from(recv_buffer.begin(), recv_buffer.end());
         std::cout << h << "\n";
      }
   };

   auto&& onReadResponse_sz = [&](auto ec, auto sz_rx)
   {
      if(sz_rx <= 0 && !ec)
      {
         std::cout << "sz read failed - " << ec.message() << "\n";
      }
      else
      {
         uint16_t sz = (recv_buffer[0] << 8) | recv_buffer[1];
         recv_buffer.resize(sz);
         boost::asio::async_read(socket, boost::asio::buffer(recv_buffer), onReadResponse);
      }
   };

   auto onWriteQuery = [&](auto ec, auto sz_tx)
   {
      if(ec)
      {
         std::cout << "write failed - " << ec.message() << "\n";
      }
      else
      {
         recv_buffer.resize(2);
         boost::asio::async_read(socket, boost::asio::buffer(recv_buffer), onReadResponse_sz);
      }
   };

   auto&& onConnect = [&](auto ec)
   {
      if(ec)
      {
         std::cout << "connect failed - " << ec.message() << "\n";
      }
      else
      {
         write_buffer.resize(2);

         for(auto c : "\36\23\1 \0\1\0\0\0\0\0\1\3www\5gmail\3com\0\0\17\0\1\0\0)\20\0\0\0\0\0\0\0"s)
            write_buffer.push_back(c);

         Dns_t::Header_t h;
         h.load_from(write_buffer.begin() + 2, write_buffer.end());
         std::cout << h << "\n";

         write_buffer[0] = ((write_buffer.size() - 2) & 0xFF00) >> 8;
         write_buffer[1] = ((write_buffer.size() - 2) & 0x00FF) >> 0;

         std::cout << OctRep(write_buffer) << "\n";

         boost::asio::async_write(socket, boost::asio::buffer(write_buffer), onWriteQuery);
      }
   };


   socket.async_connect(endpoint, onConnect);

   io.run();
}


int main(int argc, char** argv)
{
   basic_dns(argc, argv);
}
