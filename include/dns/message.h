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
         void save_to(OutputIterator o) const
         {
            auto&& tr = name_offset_tracker_t{};

            dns::save_to(tr, m_header);

            for(auto && q : m_question)
               dns::save_to(tr, q);
            for(auto && r : m_answer)
               dns::save_to(tr, r);
            for(auto && r : m_authority)
               dns::save_to(tr, r);
            for(auto && r : m_additional)
               dns::save_to(tr, r);

            std::copy(tr.cbegin(), tr.cend(), o);
         }

         template<class InputIterator>
         InputIterator load_from(InputIterator begin, InputIterator end)
         {
            auto&& tr = name_offset_tracker_t{};

            m_header = dns::load_from<dns::header_t>(tr, begin, end);
            m_question.resize(m_header.QdCount());
            m_answer.resize(m_header.AnCount());
            m_authority.resize(m_header.NsCount());
            m_additional.resize(m_header.ArCount());

            for(auto& q : m_question)
               q = dns::load_from<dns::question_t>(tr, begin, end);
            for(auto& r : m_answer)
               r = dns::load_from<dns::answer_t>(tr, begin, end);
            for(auto& r : m_authority)
               r = dns::load_from<dns::answer_t>(tr, begin, end);
            for(auto& r : m_additional)
               r = dns::load_from<dns::answer_t>(tr, begin, end);

            return begin;
         }

         friend std::ostream& operator<<(std::ostream& os, const message_t& rhs)
         {
            os << "HD: " << rhs.m_header << "\n";
            for(auto && q : rhs.m_question)
               os << "QD: " << q << "\n";
            for(auto && r : rhs.m_answer)
               os << "AN: " << r << "\n";
            for(auto && r : rhs.m_authority)
               os << "NS: " << r << "\n";
            for(auto && r : rhs.m_additional)
               os << "AR: " << r << "\n";
            return os;
         }

         header_t& Header()
         {
            return m_header;
         }

         const header_t& Header() const
         {
            return m_header;
         }

         void Question(const question_t& q)
         {
            m_question.push_back(q);
         }

         question_t& Question(int x)
         {
            return m_question.at(x);
         }

         const question_t& Question(int x) const
         {
            return m_question.at(x);
         }

         void Answer(const answer_t& q)
         {
            m_answer.push_back(q);
         }

         answer_t& Answer(int x)
         {
            return m_answer.at(x);
         }

         const answer_t& Answer(int x) const
         {
            return m_answer.at(x);
         }

         void Authority(const answer_t& q)
         {
            m_authority.push_back(q);
         }

         answer_t& Authority(int x)
         {
            return m_authority.at(x);
         }

         const answer_t& Authority(int x) const
         {
            return m_authority.at(x);
         }

         void Additional(const answer_t& q)
         {
            m_additional.push_back(q);
         }

         answer_t& Additional(int x)
         {
            return m_additional.at(x);
         }

         const answer_t& Additional(int x) const
         {
            return m_additional.at(x);
         }

      private:
         header_t m_header;
         std::vector<question_t> m_question;
         std::vector<answer_t> m_answer;
         std::vector<answer_t> m_authority;
         std::vector<answer_t> m_additional;
   };

   const message_t make_query(std::string qname, dns::rr_type_t qtype, dns::rr_class_t qclass = dns::rr_class_t::internet)
   {
      auto&& m = dns::message_t{};

      srand(time(0));

      m.Header().ID(rand());
      m.Header().RD_Flag(true);
      m.Header().AD_Flag(true);
      m.Header().QdCount(1);

      m.Question(dns::question_t{});

      m.Question(0).Name(std::move(qname));
      m.Question(0).Type(qtype);
      m.Question(0).Class(qclass);

      return m;
   }
}
