#pragma once

#include "dns/message.h"

#include <boost/asio.hpp>
#include <list>

namespace dns
{
   class resolver
   {
      public:
         resolver(boost::asio::io_service& io_service, boost::asio::ip::tcp::endpoint endpoint)
            : m_socket{io_service}
            , m_endpoint(std::move(endpoint))
         {
         }

         template<class F>
         void async_resolve(const message_t& query, F callback)
         {
            m_active_queries.push_back( std::make_unique<query_handler<F>>( query, std::move(callback) ) );

            if(!m_connect_initiated)
            {
               m_connect_initiated = true;

               m_socket.async_connect(
                  m_endpoint,
                  [this](auto ec)
               {
                  if(ec)
                  {
                     this->invoke_callback_resolve_next(ec, message_t{});
                  }
                  else
                  {
                     this->async_resolve_next();
                  }
               });
            }
         }


      private:
         template<class EC, class MSG>
         void invoke_callback_resolve_next(const EC& ec, const MSG& m)
         {
            if(!m_active_queries.empty())
            {
               m_active_queries.front()->invoke_callback(ec, m);
               
               m_active_queries.pop_front();

               this->async_resolve_next();
            }
         }

         void async_resolve_next()
         {
            if(!m_active_queries.empty())
            {
               auto&& onReadResponse = [this](auto ec, auto sz_rx)
               {
                  if(sz_rx <= 0 && !ec)
                  {
                     this->invoke_callback_resolve_next(ec, message_t{});
                  }
                  else
                  {
                     dns::message_t response;
                     response.load_from(m_active_queries.front()->m_buffer.begin(), m_active_queries.front()->m_buffer.end());

                     this->invoke_callback_resolve_next(ec, response);
                  }
               };

               auto&& onReadResponse_sz = [this, onReadResponse](auto ec, auto sz_rx)
               {
                  if(sz_rx <= 0 && !ec)
                  {
                     this->invoke_callback_resolve_next(ec, message_t{});
                  }
                  else
                  {
                     uint16_t sz = (m_active_queries.front()->m_buffer[0] << 8) | m_active_queries.front()->m_buffer[1];

                     m_active_queries.front()->m_buffer.resize(sz);
                     boost::asio::async_read(m_socket, boost::asio::buffer(m_active_queries.front()->m_buffer), onReadResponse);
                  }
               };

               auto&& onWriteQuery = [this, onReadResponse_sz](auto ec, auto sz_tx)
               {
                  if(ec)
                  {
                     this->invoke_callback_resolve_next(ec, message_t{});
                  }
                  else
                  {
                     m_active_queries.front()->m_buffer.resize(2);
                     boost::asio::async_read(m_socket, boost::asio::buffer(m_active_queries.front()->m_buffer), onReadResponse_sz);
                  }
               };

               boost::asio::async_write(m_socket, boost::asio::buffer(m_active_queries.front()->m_buffer), onWriteQuery);
            }
         }

      private:
         boost::asio::ip::tcp::socket m_socket;
         boost::asio::ip::tcp::endpoint m_endpoint;

         bool m_connect_initiated = false;

         struct query_handler_base
         {
            query_handler_base(const message_t& query)
            {
               m_buffer.resize(2);
               query.save_to(std::back_inserter(m_buffer));
               m_buffer[0] = ((m_buffer.size() - 2) & 0xFF00) >> 8;
               m_buffer[1] = ((m_buffer.size() - 2) & 0x00FF) >> 0;
            }

         public:
            virtual void invoke_callback( const boost::system::error_code&, const dns::message_t& ) = 0;
            virtual ~query_handler_base() = default;

            query_handler_base() = default;
            query_handler_base(const query_handler_base&) = default;
            query_handler_base(query_handler_base&&) = default;
            query_handler_base& operator=(const query_handler_base&) = default;
            query_handler_base& operator=(query_handler_base&&) = default;
           
         public:
            std::vector<uint8_t> m_buffer;
         };

         template<class F>
         struct query_handler : query_handler_base
         {
            query_handler(const message_t& query, F callback)
               : query_handler_base(query)
               , m_callback( std::move(callback) )
            {
            }

            virtual void invoke_callback( const boost::system::error_code& ec, const dns::message_t& msg) final override
            {
               m_callback(ec, msg);
            }

            F m_callback;
         };

         std::list<std::unique_ptr<query_handler_base>> m_active_queries;
   };
}
