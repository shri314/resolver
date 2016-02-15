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

#include "Resolver.h"
using namespace std::string_literals;

/**
 * TODO:
 *
 * 1) Resolver - Async send
 *
 * 1) Record Data Types - MX Record
 *
 * 1) Offset interpretation from raw data
 *
 * 1) Offset determination during construction
 *
 * 1) Resolver - Async recv, incremental parse/receive to build/recv object
 *
 * 1) async_resolve - callback - iterator interface
 *
 * 1) Other Record Data Types - TXT Record, NS Record
 *
 * 1) Enum for QType, QClass
 *
 * 1) Response Builder (server side)
 *
 *    DnsProtocol::Response().WithID()...
 *                 .AddQuestionNamed(n).WithQType(1).WithQClass(2)
 *                 .AddAnswer().WithType(t).WithPreference().WithMXData().WithPreference().WithName("mx.n.com")
 *                 .AddAuthority().WithNS(ns)...
 *                 .AddAuthority().WithNS(ns)...
 *                 .AddAdditional().Withxx(yy)...
 *
 * 1) Templatetize the access to m_store pod elements layout, <uint8_t, uint8_t, uint16_t>
 *
 * 1) Templatetize? Boostize?
 */

/*
void handle_dns_answers(DnsProtocol::Response::iterator iter)
{
}
*/

int main(int argc, char** argv)
{
   asio::io_service io_service;
   // resolver resolver(io_service);

   boost::asio::ip::tcp::endpoint dns_endpoint(boost::asio::ip::address::from_string("8.8.8.8"), 53);

   DnsProtocol::Resolver dns_resolver(io_service, dns_endpoint);

   std::vector<uint8_t> stor;
   DnsProtocol::Header_t h(stor);
   std::string s = "|s\1 \0\1\0\0\0\0\0\1"s; // \7hotmail\3com\0\0\17\0\1\0\0)\20\0\0\0\0\0\0\0";
   auto b = s.begin();
   auto e = s.end();
   h.Load(b, e);

   std::cout << h << "\n";

   for(int i = 1; i < argc; ++i)
   {
      auto&& pDNSReq = DnsProtocol::Query().WithID(31859).WithRecurrsion()
                       .AddQuestionNamed(argv[i]).WithQType(0xF).WithQClass(1)
                       .Build();

      std::cout << *pDNSReq << "\n";

      dns_resolver.async_resolve( std::move(pDNSReq) );

      /*
      dns_resolver.async_resolve(
         DnsProtocol::Query()
            .WithID(rand() % 65536)
            .WithRecurrsion()
         .AddQuestionNamed(argv[i])
            .WithQType(1)
            .WithQClass(2)
         .Build(),

         handle_dns_answers
      );
      */

      /*
      resolver.async_resolve(
         resolver::query(argv[i], "http"),
         handle_resolve_query
      );
      */
   }

   io_service.run();

   return 0;
}
