#pragma once

#include "dns/message.h"

#include <boost/asio.hpp>
#include <list>

namespace dns::udp
{
   class resolver
   {
      public:
         resolver(boost::asio::io_service& io_service, boost::asio::ip::udp::endpoint endpoint)
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

               boost::system::error_code ec;
               m_socket.open( m_endpoint.protocol(), ec );

               if(ec)
               {
                  this->invoke_callback_resolve_next(ec, message_t{});
               }
               else
               {
                  this->async_resolve_next();
               }
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

               auto&& onWriteQuery = [this, onReadResponse](auto ec, auto sz_tx)
               {
                  if(ec)
                  {
                     this->invoke_callback_resolve_next(ec, message_t{});
                  }
                  else
                  {
                     m_active_queries.front()->m_buffer.resize(65535);

                     m_socket.async_receive_from(boost::asio::buffer(m_active_queries.front()->m_buffer), m_endpoint, onReadResponse);
                  }
               };

               // m_socket.open();
               m_socket.async_send_to(boost::asio::buffer(m_active_queries.front()->m_buffer), m_endpoint, onWriteQuery);
            }
         }

      private:
         boost::asio::ip::udp::socket m_socket;
         boost::asio::ip::udp::endpoint m_endpoint;

         bool m_connect_initiated = false;

         struct query_handler_base
         {
            query_handler_base(const message_t& query)
            {
               query.save_to(std::back_inserter(m_buffer));
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
