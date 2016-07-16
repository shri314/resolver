#ifndef Dns_h__
#define Dns_h__

#include <string>
#include <vector>
#include <ostream>
#include <memory>    // std::unique_ptr
#include <algorithm> // std::copy
#include <boost/asio/buffer.hpp>

#include "Header.h"
#include "LabelList.h"
#include "Question.h"
#include "ResourceRecord.h"

namespace DnsProtocol
{
   class Dns_t;

   namespace detail
   {
      class query_builder;
      class question_builder;
   }

   class Dns_t
   {
      public:
         friend class detail::query_builder;
         friend class detail::question_builder;

         Dns_t()
            : m_Header(m_store)
         {
         }

         Dns_t(Dns_t&& rhs) = delete;
         Dns_t(const Dns_t& rhs) = delete;
         void operator=(const Dns_t& rhs) = delete;
         void operator=(Dns_t&& rhs) = delete;

         const Header_t& Header() const
         {
            return m_Header;
         }

         const Question_t& Question(uint16_t x) const
         {
            return m_Question.at(x);
         }

         const ResourceRecord_t& Answer(uint16_t x) const
         {
            return m_Answer.at(x);
         }

         const ResourceRecord_t& Authority(uint16_t x) const
         {
            return m_Authority.at(x);
         }

         const ResourceRecord_t& Additional(uint16_t x) const
         {
            return m_Additional.at(x);
         }

         uint16_t Size() const
         {
            uint16_t sz = m_Header.Size();
            for(auto && qn : m_Question)   sz += qn.Size();
            for(auto && an : m_Answer)     sz += an.Size();
            for(auto && au : m_Authority)  sz += au.Size();
            for(auto && ad : m_Additional) sz += ad.Size();

            return sz;
         }

         void Clear()
         {
            while(!m_Additional.empty()) m_Additional.pop_back();
            while(!m_Authority.empty()) m_Authority.pop_back();
            while(!m_Answer.empty()) m_Answer.pop_back();
            while(!m_Question.empty()) m_Question.pop_back();
         }

         friend std::ostream& operator<<(std::ostream& os, const Dns_t& rhs)
         {
            std::string sep = "";

            {
               os << sep << "HEADER     : [ " << rhs.m_Header;
               os << " ]";
               sep = "\n";
            }

            if(!rhs.m_Question.empty())
            {
               os << sep << "QUESTION   : [ ";
               sep.clear();
               for(auto && rr : rhs.m_Question)   { os << sep << rr; sep = ", "; }
               os << " ]";
               sep = "\n";
            }

            if(!rhs.m_Answer.empty())
            {
               os << sep << "ANSWER     : [ ";
               sep.clear();
               for(auto && rr : rhs.m_Answer)   { os << sep << rr; sep = ", "; }
               os << " ]";
               sep = "\n";
            }

            if(!rhs.m_Authority.empty())
            {
               os << sep << "AUTHORITY  : [ ";
               sep.clear();
               for(auto && rr : rhs.m_Authority)   { os << sep << rr; sep = ", "; }
               os << " ]";
               sep = "\n";
            }

            if(!rhs.m_Additional.empty())
            {
               os << sep << "ADDITIONAL : [ ";
               sep.clear();
               for(auto && rr : rhs.m_Additional)   { os << sep << rr; sep = ", "; }
               os << " ]";
               sep = "\n";
            }

            return os;
         }

         ~Dns_t()
         {
            this->Clear();
         }

         void Save(std::vector<boost::asio::const_buffer>& buf) const
         {
            buf.push_back(boost::asio::const_buffer{&m_store[0], m_store.size()});
         }

         void Save(std::vector<uint8_t>& buf) const
         {
            std::copy(m_store.begin(), m_store.end(), std::back_inserter(buf));
         }

         auto Save() const
         {
            return m_store;
         }

         auto Buffer() const
         {
            return boost::asio::buffer(&m_store[0], m_store.size());
         }

      private:
         std::vector<uint8_t> m_store;

         Header_t m_Header;
         std::vector<Question_t> m_Question;
         std::vector<ResourceRecord_t> m_Answer;
         std::vector<ResourceRecord_t> m_Authority;
         std::vector<ResourceRecord_t> m_Additional;
   };
}

#include "detail/query_builder.h"
#include "detail/response_builder.h"

namespace DnsProtocol
{
   detail::query_builder Query()
   {
      return detail::query_builder(std::make_unique<Dns_t>());
   }
}

#endif
