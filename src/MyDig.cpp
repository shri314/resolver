#include "dns/tcp/resolver.h"
#include "dns/udp/resolver.h"

#include <iostream>
#include <string>

using namespace std::string_literals;

int basic_dns(int argc, char** argv) try
{
   auto&& next_argv = [&argv, &argc]() -> std::string
   {
      static auto self_name = [&]() { return --argc, *argv++; }();

      if(--argc < 0)
      {
         std::cerr << "Usage: " << self_name << " <dns_server_ip> <tcp|udp> <mx|a|txt|soa|ptr|ns|any> <query_str>\n";
         throw 1;
      }

      return *argv++;
   };

   auto&& dns_host = next_argv();
   auto&& tcp_or_udp = next_argv();
   auto&& qtype_str = next_argv();
   auto&& qname = next_argv();

   auto&& qtype = [&]()
   {
      if(false);
      else if(qtype_str == "mx")   return dns::rr_type_t::rec_mx;
      else if(qtype_str == "ptr")  return dns::rr_type_t::rec_ptr;
      else if(qtype_str == "ns")   return dns::rr_type_t::rec_ns;
      else if(qtype_str == "a")    return dns::rr_type_t::rec_a;
      else if(qtype_str == "txt")  return dns::rr_type_t::rec_txt;
      else if(qtype_str == "soa")  return dns::rr_type_t::rec_soa;
      else if(qtype_str == "any")  return dns::rr_type_t::rec_any;
      else
      {
         std::cerr << "unsupported record type: " << qtype_str << "\n";
         throw 1;
      }
   }();

   {
      auto&& io = boost::asio::io_service{};

      if( tcp_or_udp == "tcp" )
      {
         auto&& endpoint = boost::asio::ip::tcp::endpoint{boost::asio::ip::address::from_string(dns_host), 53};

         dns::tcp::resolver r{io, endpoint};

         r.async_resolve(
            dns::make_query(qname, qtype),
            [](auto ec, auto msg)
         {
            std::cout << msg;
         });

         io.run();
      }
      else if( tcp_or_udp == "udp" )
      {
         auto&& endpoint = boost::asio::ip::udp::endpoint{boost::asio::ip::address::from_string(dns_host), 53};

         dns::udp::resolver r{io, endpoint};

         r.async_resolve(
            dns::make_query(qname, qtype),
            [](auto ec, auto msg)
         {
            std::cout << msg;
         });

         io.run();
      }
      else
      {
         std::cerr << "unsupported protocol type: " << tcp_or_udp << "\n";
         throw 1;
      }
   }

   return 0;
}
catch(...)
{
   return 1;
}

int main(int argc, char** argv)
{
   return basic_dns(argc, argv);
}
