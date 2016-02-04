#pragma once

namespace DnsProtocol
{
   namespace detail
   {
      class query_builder;
      class question_builder;

      class query_builder
      {
         public:
            friend class Dns_t;

            inline explicit query_builder(std::unique_ptr<Dns_t> pDNS);

            inline query_builder& WithRecurrsion();
            inline query_builder& WithID(uint16_t v);

            inline question_builder AddQuestion(const std::string& name, uint16_t qtype, uint16_t qclass);
            inline question_builder AddQuestionNamed(const std::string& name);

            query_builder(query_builder&& rhs) = default;
            query_builder(const query_builder&) = delete;
            void operator=(query_builder&&) = delete;
            void operator=(const query_builder&) = delete;

         private:
            std::unique_ptr<Dns_t> m_pDNS;
      };

      class question_builder
      {
         public:
            friend class Dns_t;

            inline explicit question_builder(std::unique_ptr<Dns_t> pDNS, const std::string& name);

            inline question_builder& WithQType(uint16_t v);
            inline question_builder& WithQClass(uint16_t v);

            inline question_builder AddQuestion(const std::string& name, uint16_t qtype, uint16_t qclass);
            inline question_builder AddQuestionNamed(const std::string& name);

            inline std::unique_ptr<Dns_t> Build();

            question_builder(question_builder&& rhs) = default;
            question_builder(const question_builder&) = delete;
            void operator=(question_builder&&) = delete;
            void operator=(const question_builder&) = delete;

         private:
            std::unique_ptr<Dns_t> m_pDNS;
      };

      query_builder::query_builder(std::unique_ptr<Dns_t> pDNS)
         : m_pDNS(std::move(pDNS))
      {
         m_pDNS->Clear();

         m_pDNS->m_Header
         .ID(0)
         .QR_Flag(0)
         .AA_Flag(0)
         .TC_Flag(0)
         .RD_Flag(0)
         .RA_Flag(0)
         .OpCode(0)
         .ZCode(0)
         .RCode(0)
         .QdCount(0)
         .AnCount(0)
         .NsCount(0)
         .ArCount(0);
      }

      query_builder& query_builder::WithRecurrsion()
      {
         m_pDNS->m_Header.RD_Flag(1);

         return *this;
      }

      query_builder& query_builder::WithID(uint16_t v)
      {
         m_pDNS->m_Header.ID(v);

         return *this;
      }

      question_builder query_builder::AddQuestionNamed(const std::string& name)
      {
         return question_builder(std::move(m_pDNS), name);
      }

      question_builder query_builder::AddQuestion(const std::string& name, uint16_t qtype, uint16_t qclass)
      {
         return std::move(AddQuestionNamed(name).WithQType(qtype).WithQClass(qclass));
      }

      question_builder::question_builder(std::unique_ptr<Dns_t> rhs, const std::string& name)
         : m_pDNS(std::move(rhs))
      {
         m_pDNS->m_Question.emplace_back(Question_t(m_pDNS->m_store));

         m_pDNS->m_Header.QdCount(m_pDNS->m_Question.size());

         m_pDNS->m_Question.back().QName(name);
      }

      question_builder& question_builder::WithQType(uint16_t v)
      {
         m_pDNS->m_Question.back().QType(v);

         return *this;
      }

      question_builder& question_builder::WithQClass(uint16_t v)
      {
         m_pDNS->m_Question.back().QClass(v);

         return *this;
      }

      question_builder question_builder::AddQuestionNamed(const std::string& name)
      {
         return question_builder(std::move(m_pDNS), name);
      }

      question_builder question_builder::AddQuestion(const std::string& name, uint16_t qtype, uint16_t qclass)
      {
         return std::move(AddQuestionNamed(name).WithQType(qtype).WithQClass(qclass));
      }

      std::unique_ptr<Dns_t> question_builder::Build()
      {
         return std::move(m_pDNS);
      }
   }
}
