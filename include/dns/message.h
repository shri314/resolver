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
         void save_to(OutputIterator o)
         {
            name_offset_tracker_t tr;

            dns::save_to(tr, m_header);

            for(auto&& q : m_question)
               dns::save_to(tr, q);
            for(auto&& r : m_answer)
               dns::save_to(tr, r);
            for(auto&& r : m_authority)
               dns::save_to(tr, r);
            for(auto&& r : m_additional)
               dns::save_to(tr, r);

            std::copy(tr.store().begin(), tr.store().end(), o);
         }

         template<class InputIterator>
         InputIterator load_from(InputIterator cur_pos, InputIterator end)
         {
            name_offset_tracker_t tr;

            dns::load_from(tr, cur_pos, end, m_header);

            m_question.resize( m_header.QDCount() );
            m_answer.resize( m_header.ANCount() );
            m_authority.resize( m_header.NSCount() );
            m_additional.resize( m_header.ARCount() );

            for(auto&& q : m_question)
               dns::load_from(tr, cur_pos, end, q);
            for(auto&& r : m_answer)
               dns::load_from(tr, cur_pos, end, r);
            for(auto&& r : m_authority)
               dns::load_from(tr, cur_pos, end, r);
            for(auto&& r : m_additional)
               dns::load_from(tr, cur_pos, end, r);

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
