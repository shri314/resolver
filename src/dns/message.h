#pragma once

#include "dns/header.h"
#include "dns/question.h"
#include "dns/record.h"

#include <ostream>
#include <string>
#include <vector>

namespace dns
{
   class message_t
   {
      public:
         template<class OutputIterator>
         OutputIterator save_to(OutputIterator o)
         {
            name_offset_tracker_t L;

            o = m_header.save_to(o, &L);
            for(auto&& q : m_question)
               o = q.save_to(o, &L);
            for(auto&& r : m_answer)
               o = r.save_to(o, &L);
            for(auto&& r : m_authority)
               o = r.save_to(o, &L);
            for(auto&& r : m_additional)
               o = r.save_to(o, &L);

            return o;
         }

         template<class InputIterator>
         InputIterator load_from(InputIterator cur_pos, InputIterator end)
         {
            cur_pos = m_header.load_from(cur_pos, end);

            m_question.resize( m_header.QDCount() );
            m_answer.resize( m_header.ANCount() );
            m_authority.resize( m_header.NSCount() );
            m_additional.resize( m_header.ARCount() );

            for(auto&& q : m_question)
               cur_pos = q.load_from(cur_pos, end);
            for(auto&& r : m_answer)
               cur_pos = r.load_from(cur_pos, end);
            for(auto&& r : m_authority)
               cur_pos = r.load_from(cur_pos, end);
            for(auto&& r : m_additional)
               cur_pos = r.load_from(cur_pos, end);

            return cur_pos;
         }

         friend std::ostream& operator<<(std::ostream& os, const header_t& rhs)
         {
            return os;
         }

         void Question(const question_t& q)
         {
            m_question.push_back(q);
         }

         Question& Question(int x)
         {
            m_question.at(x);
         }

         const Question& Question(int x) const
         {
            m_question.at(x);
         }

         void Answer(const record_t& q)
         {
            m_answer.push_back(q);
         }

         record_t& Answer(int x)
         {
            m_answer.at(x);
         }

         const record_t& Answer(int x) const
         {
            m_answer.at(x);
         }

         void Authority(const record_t& q)
         {
            m_authority.push_back(q);
         }

         record_t& Authority(int x)
         {
            m_authority.at(x);
         }

         const record_t& Authority(int x) const
         {
            m_authority.at(x);
         }

         void Additional(const record_t& q)
         {
            m_additional.push_back(q);
         }

         record_t& Additional(int x)
         {
            m_additional.at(x);
         }

         const record_t& Additional(int x) const
         {
            m_additional.at(x);
         }

      private:
         header_t m_header;
         std::vector<question_t> m_question;
         std::vector<record_t> m_answer;
         std::vector<record_t> m_authority;
         std::vector<record_t> m_additional;
   };
}
