#include <boost/asio.hpp>
#include <iostream>

#define ALIGNAS alignas(1)

class DnsProtocol
{
      struct ALIGNAS HeaderPod
      {
         private:
            uint16_t m_ID;
            uint16_t m_Flags;
            uint16_t m_QDCount;
            uint16_t m_AnCount;
            uint16_t m_NsCount;
            uint16_t m_ArCount;

         public:
            void ID(uint16_t ID_)
            {
               m_ID = ID_;
            }

            uint16_t ID() const
            {
               return m_ID;
            }

            void QR_Flag(bool b)
            {
               m_Flags |= (b ? 0x8000 : 0x0000);
            }

            bool QR_Flag() const
            {
               return m_Flags & 0x8000 == 0x8000;
            }

            void OPCode(uint8_t OPCode_)
            {
               return m_Flags | (OpCode_ & 0xF) << 11;
            }

            uint8_t OPCode() const
            {
               return (m_Flags & 0x7800) >> 11;
            }

            void AA_Flag(bool b)
            {
               m_Flags |= (b ? 0x0400 : 0x0000);
            }

            bool AA_Flag() const
            {
               return m_Flags & 0x0400 == 0x0400;
            }

            void TC_Flag(bool b)
            {
               m_Flags |= (b ? 0x0200 : 0x0000);
            }

            bool TC_Flag() const
            {
               return m_Flags & 0x0200 == 0x0200;
            }

            void RD_Flag(bool b)
            {
               m_Flags |= (b ? 0x0100 : 0x0000);
            }

            bool RD_Flag() const
            {
               return m_Flags & 0x0100 == 0x0100;
            }

            void RA_Flag(bool b)
            {
               m_Flags |= (b ? 0x0080 : 0x0000);
            }

            bool RA_Flag() const
            {
               return m_Flags & 0x0080 == 0x0080;
            }

            void Z_Flag()
            {
               m_Flags &= ~0x0070;
            }

            void RCode(uint8_t RCode_)
            {
               return m_Flags | (RCode_ & 0xF);
            }

            uint8_t RCode() const
            {
               return (m_Flags & 0xF);
            }

            void QDCount(uint16_t QDCount_)
            {
               m_QDCount = QDCount_;
            }

            uint16_t QDCount() const
            {
               return m_QDCount;
            }

            void ANCount(uint16_t ANCount_)
            {
               m_ANCount = ANCount_;
            }

            uint16_t ANCount() const
            {
               return m_ANCount;
            }

            void NSCount(uint16_t NSCount_)
            {
               m_NSCount = NSCount_;
            }

            uint16_t NSCount() const
            {
               return m_NSCount;
            }

            void ARCount(uint16_t ARCount_)
            {
               m_ARCount = ARCount_;
            }

            uint16_t ARCount() const
            {
               return m_ARCount;
            }

      } m_Header;

      struct ALIGNAS QuestionPod
      {
      };
};






namespace asio = boost::asio;
typedef asio::ip::tcp protocol;
typedef protocol::resolver resolver;

typedef boost::system::error_code error_code;

void handle_resolve_query(const error_code& ec, resolver::iterator iter)
{
   if(ec) return;

   resolver::iterator end;
   for(; iter != end; ++iter)
   {
      protocol::endpoint endpoint = *iter;
      std::cout << endpoint << std::endl;
   }
}

#include <iostream>
using std::cout;

int main(int argc, char** argv)
{
   asio::io_service io_service;
   resolver resolver(io_service);

   for(int i = 1; i < argc; ++i)
   {
      resolver.async_resolve(resolver::query(argv[i], "http"), handle_resolve_query);
   }

   io_service.run();

   cout << sizeof(DnsHeader) << "\n";

   return 0;
}
