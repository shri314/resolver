#pragma once

#include "dns/header.h"
#include "dns/question.h"
#include "dns/answer.h"

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

            m_header = dns::load_from<dns::header_t>(tr, cur_pos, end);
            m_question.resize( m_header.QDCount() );
            m_answer.resize( m_header.ANCount() );
            m_authority.resize( m_header.NSCount() );
            m_additional.resize( m_header.ARCount() );

            for(auto& q : m_question)
               q = dns::load_from<dns::question_t>(tr, cur_pos, end);
            for(auto& r : m_answer)
               r = dns::load_from<dns::answer_t>(tr, cur_pos, end);
            for(auto& r : m_authority)
               r = dns::load_from<dns::answer_t>(tr, cur_pos, end);
            for(auto& r : m_additional)
               r = dns::load_from<dns::answer_t>(tr, cur_pos, end);

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

         void Answer(const answer_t& q)
         {
            m_answer.push_back(q);
         }

         answer_t& Answer(int x)
         {
            m_answer.at(x);
         }

         const answer_t& Answer(int x) const
         {
            m_answer.at(x);
         }

         void Authority(const answer_t& q)
         {
            m_authority.push_back(q);
         }

         answer_t& Authority(int x)
         {
            m_authority.at(x);
         }

         const answer_t& Authority(int x) const
         {
            m_authority.at(x);
         }

         void Additional(const answer_t& q)
         {
            m_additional.push_back(q);
         }

         answer_t& Additional(int x)
         {
            m_additional.at(x);
         }

         const answer_t& Additional(int x) const
         {
            m_additional.at(x);
         }

      private:
         header_t m_header;
         std::vector<question_t> m_question;
         std::vector<answer_t> m_answer;
         std::vector<answer_t> m_authority;
         std::vector<answer_t> m_additional;
   };
}
