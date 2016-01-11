#include "Dns.h"

#include <boost/asio.hpp>
#include <iostream>

using std::cout;







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

int main(int argc, char** argv)
{
   asio::io_service io_service;
   resolver resolver(io_service);

   for(int i = 1; i < argc; ++i)
   {
      resolver.async_resolve(resolver::query(argv[i], "http"), handle_resolve_query);
   }

   io_service.run();


   DnsProtocol::LabelList_t qn;
   
   qn.Set("www.yahoo.com");

   std::ostringstream oss; oss << qn;

   assert( oss.str() == "[3]www[5]yahoo[3]com[0]" );

   cout << oss.str() << "\n";

   return 0;
}
