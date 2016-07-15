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

#include "dns/header.h"
#include "dns/question.h"

void basic_dns(int argc, char** argv)
{
   --argc; ++argv;

   if(argc <= 0)
      return;

   std::string dns_host = *argv;

   boost::asio::io_service io;
   boost::asio::ip::tcp::endpoint endpoint(boost::asio::ip::address::from_string(dns_host), 53);
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

         dns::header_t h;
         dns::name_offset_tracker_t tr;
         auto&& b = recv_buffer.begin();
         auto&& e = recv_buffer.end();
         dns::load_from(tr, b, e, h);
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

         dns::header_t h;
         dns::name_offset_tracker_t tr;
         auto&& b = write_buffer.begin() + 2;
         auto&& e = write_buffer.end();
         dns::load_from(tr, b, e, h);
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
