#ifndef Dns_h__
#define Dns_h__

#include <string>
#include <vector>
#include <ostream>
#include <algorithm> // std::copy
#include <boost/asio/buffer.hpp>

#include "Header.h"
#include "LabelList.h"
#include "Question.h"
#include "ResourceRecord.h"

namespace DnsProtocol
{
   struct Dns_t
   {
      public:
         Dns_t()
            : m_Header( m_store )
         {
         }

         const Header_t& Header() const
         {
            return m_Header;
         }

         Header_t& Header()
         {
            return m_Header;
         }

         Question_t& Question(uint16_t x)
         {
            // m_Question.resize(m_Header.QdCount());

            return m_Question.at(x);
         }

         ResourceRecord_t& Answer(uint16_t x)
         {
            // m_Answer.resize(m_Header.AnCount());

            return m_Answer.at(x);
         }

         ResourceRecord_t& Authority(uint16_t x)
         {
            // m_Authority.resize(m_Header.NsCount());

            return m_Authority.at(x);
         }

         ResourceRecord_t& Additional(uint16_t x)
         {
            // m_Additional.resize(m_Header.ArCount());

            return m_Additional.at(x);
         }

         uint16_t Size() const
         {
            uint16_t sz = m_Header.Size();
            for(auto&& qn : m_Question)   sz += qn.Size();
            for(auto&& an : m_Answer)     sz += an.Size();
            for(auto&& au : m_Authority)  sz += au.Size();
            for(auto&& ad : m_Additional) sz += ad.Size();

            return sz;
         }

      private:
         /*
         uint16_t FindOffset(const std::string& label)
         {
            uint16_t finalOffset = m_Header.Size();

            for(auto&& qn : m_Question)
            {
               uint16_t off = qn.OffsetOf(label);

               if(off != -1)
               {
                  return finalOffset + off;
               }
               else
               {
                  finalOffset += m_Question.Size();
               }
            }

            return 0; // anything less then 12 can't be a valid offset
         }

         uint16_t FindOffset(const std::string& label)
         {
            uint16_t finalOffset = m_Header.Size();

            for(auto&& qn : m_Question)
            {
               uint16_t off = qn.OffsetOf(label);

               if(off != -1)
               {
                  return finalOffset + off;
               }
               else
               {
                  finalOffset += m_Question.Size();
               }
            }

            return 0; // anything less then 12 can't be a valid offset
         }
         */

      private:
         std::vector<uint8_t> m_store;
         std::vector<LabelList_t> m_OtherLabels;

      private:
         Header_t m_Header;
         std::vector<Question_t> m_Question;
         std::vector<ResourceRecord_t> m_Answer;
         std::vector<ResourceRecord_t> m_Authority;
         std::vector<ResourceRecord_t> m_Additional;
   };
};

#endif
