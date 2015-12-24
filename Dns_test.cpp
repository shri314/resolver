#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE Dns_test
#include <boost/test/unit_test.hpp>

#include "Dns.h"

#include <sstream>
#include <iostream>

BOOST_AUTO_TEST_CASE(qname_serialization)
{
   {
      DnsProtocol::QName qn{"www.yahoo.com"};

      std::ostringstream oss;
      oss << qn;

      BOOST_TEST(oss.str() == "[3]www[5]yahoo[3]com[0]");
   }

   {
      DnsProtocol::QName qn{"www.yahoo.com"};

      std::ostringstream oss;

      qn.FillData(oss);

      BOOST_TEST( oss.str() == "\003www\005yahoo\003com" + std::string(1, '\0') );
   }
}
