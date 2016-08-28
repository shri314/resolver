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

#include "util/oct_dump.h"

#include "dns/header.h"
#include "dns/question.h"
#include "dns/record.h"

int basic_dns(int argc, char** argv)
{
   std::string self_name = *argv;
   --argc;
   ++argv;

   if(argc <= 2)
   {
      std::cerr << "Usage: " << self_name << " <dns_server_ip> <mx|a|txt|soa|ptr|ns|any> <query_str>\n";
      return 1;
   }

   std::string dns_host = *argv;
   ++argv;
   --argc;

   std::string qtype_str = *argv;
   ++argv;
   --argc;

   std::string qname = *argv;
   ++argv;
   --argc;

   dns::rr_type_t qtype;
   if(false);
   else if(qtype_str == "mx")   qtype = dns::rr_type_t::rec_mx;
   else if(qtype_str == "ptr")  qtype = dns::rr_type_t::rec_ptr;
   else if(qtype_str == "ns")   qtype = dns::rr_type_t::rec_ns;
   else if(qtype_str == "a")    qtype = dns::rr_type_t::rec_a;
   else if(qtype_str == "txt")  qtype = dns::rr_type_t::rec_txt;
   else if(qtype_str == "soa")  qtype = dns::rr_type_t::rec_soa;
   else if(qtype_str == "any")  qtype = dns::rr_type_t::rec_any;
   else
   {
      std::cerr << "unsupported record type: " << qtype_str << "\n";
      return 1;
   }

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
         // std::cout << util::oct_dump(std::string(recv_buffer.begin(), recv_buffer.begin() + sz_rx)) << "\n";

         try
         {
            auto&& b = recv_buffer.begin();
            auto&& e = recv_buffer.end();
            auto&& tr = dns::name_offset_tracker_t{};

            auto&& h = dns::load_from<dns::header_t>(tr, b, e);
            std::cout << "S: HD: " << h << "\n";

            for(int i = 0; i < h.QdCount(); ++i)
               std::cout << "S: QD: " << dns::load_from<dns::question_t>(tr, b, e) << "\n";

            for(int i = 0; i < h.AnCount(); ++i)
            {
               auto&& r = dns::load_from<dns::record_t>(tr, b, e);
               std::cout << "S: AN: " << r << "\n";

               // r.get_as<dns::mx_record_t>
            }

            for(int i = 0; i < h.NsCount(); ++i)
               std::cout << "S: NS: " << dns::load_from<dns::record_t>(tr, b, e) << "\n";

            for(int i = 0; i < h.ArCount(); ++i)
               std::cout << "S: AR: " << dns::load_from<dns::record_t>(tr, b, e) << "\n";
         }
         catch(const std::exception& e)
         {
            std::cout << "S: XX - " << e.what() << "\n";
         }
      }
   };

   auto&& onReadResponse_sz = [&](auto ec, auto sz_rx)
   {
      if(sz_rx <= 0 && !ec)
      {
         std::cout << sz_rx << "\n";
         std::cout << "sz read failed - " << ec.message() << "\n";
      }
      else
      {
         uint16_t sz = (recv_buffer[0] << 8) | recv_buffer[1];

         // std::cout << "expect sz = " << sz << "\n";
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

         srand(time(0));

         {
            auto&& tr = dns::name_offset_tracker_t{};

            {
               auto&& h = dns::header_t{};

               h.ID(rand());
               h.RD_Flag(true);
               h.AD_Flag(true);
               h.QdCount(1);

               std::cout << "C: HD: " << h << "\n";
               dns::save_to(tr, h);
            }

            {
               auto&& q = dns::question_t{};

               q.Name(qname);
               q.Type(qtype);
               q.Class(dns::rr_class_t::internet);

               std::cout << "C: QD: " << q << "\n";
               dns::save_to(tr, q);
            }

            auto&& oi = std::back_inserter(write_buffer);
            std::copy(tr.cbegin(), tr.cend(), oi);
         }

         write_buffer[0] = ((write_buffer.size() - 2) & 0xFF00) >> 8;
         write_buffer[1] = ((write_buffer.size() - 2) & 0x00FF) >> 0;

         // std::cout << util::oct_dump(write_buffer) << "\n";

         boost::asio::async_write(socket, boost::asio::buffer(write_buffer), onWriteQuery);
      }
   };

   socket.async_connect(endpoint, onConnect);

   io.run();

   return 0;
}


int main(int argc, char** argv)
{
   return basic_dns(argc, argv);
}
