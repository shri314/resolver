#include "Dns.h"

#include <boost/asio.hpp>

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

   std::vector< std::unique_ptr<DnsProtocol::Dns_t> > res;

   for(int i = 1; i < argc; ++i)
   {
      auto&& pDNS = DnsProtocol::Query().WithID(rand() % 65536).WithRecurrsion()
                    .AddQuestionNamed(argv[i]).WithQType(1).WithQClass(2)
                    .Build();

      std::cout << *pDNS << "\n";

      res.emplace_back(std::move(pDNS));

      resolver.async_resolve(resolver::query(argv[i], "http"), handle_resolve_query);
   }

   io_service.run();

   return 0;
}
