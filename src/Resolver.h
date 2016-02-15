#include "Dns.h"

#include <memory> // unique_ptr
#include <boost/asio.hpp>

#include "raw_dump.h"

namespace DnsProtocol
{
   class Dns_t;
   class Resolver
   {
      public:

         Resolver(
            boost::asio::io_service& io_service,
            boost::asio::ip::tcp::endpoint dns_endpoint
         )
            : m_io_service(io_service)
            , m_dns_endpoint(dns_endpoint)
            , m_socket(m_io_service)
         {
         }

         void async_resolve(std::unique_ptr<Dns_t> query)
         {
            m_query = std::move(query);

            auto&& onConnect = [this](auto ec)
            {
               if(!ec)
               {
                  this->write_query();
               }
            };

            m_socket.async_connect( m_dns_endpoint, onConnect );
         }

      private:
         void write_query()
         {
            auto&& onWriteQuery = [this](auto ec, auto sz_tx) {
               if(!ec)
               {
                  this->read_response();
               }
            };

            boost::asio::async_write( m_socket, m_query->Buffer(), onWriteQuery );
         }

         void read_response()
         {
            auto&& onReadResponse = [this](auto ec, auto sz_rx) {
               if(!ec)
               {
                  std::cout << m_recv_buffer.size() << "\n";
                  std::cout << sz_rx << "\n";
               }
            };

            m_recv_buffer.resize(64 * 1024);

            boost::asio::async_read( m_socket, boost::asio::buffer(m_recv_buffer), onReadResponse );
         }

      private:
         std::unique_ptr<Dns_t> m_query;
         std::vector<uint8_t> m_recv_buffer;
         std::unique_ptr<Dns_t> m_response;

         boost::asio::io_service& m_io_service;
         boost::asio::ip::tcp::endpoint m_dns_endpoint;
         boost::asio::ip::tcp::socket m_socket;
   };
}
