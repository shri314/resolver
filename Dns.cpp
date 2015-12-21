#include <boost/asio.hpp>
#include <iostream>


struct alignas(2) DnsHeader
{
   uint16_t ID;
   uint16_t Flags;
   uint16_t QDCount;
   uint16_t AnCount;
   uint16_t NsCount;
   uint16_t ArCount;
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
