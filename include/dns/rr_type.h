#pragma once

#include <ostream>

namespace dns
{
   enum class rr_type_t : uint16_t
   {
      rec_a          = 1,     /* a host address,[RFC1035], */
      rec_ns         = 2,     /* an authoritative name server,[RFC1035], */
      rec_md         = 3,     /* a mail destination (OBSOLETE - use MX),[RFC1035], */
      rec_mf         = 4,     /* a mail forwarder (OBSOLETE - use MX),[RFC1035], */
      rec_cname      = 5,     /* the canonical name for an alias,[RFC1035], */
      rec_soa        = 6,     /* marks the start of a zone of authority,[RFC1035], */
      rec_mb         = 7,     /* a mailbox domain name (EXPERIMENTAL),[RFC1035], */
      rec_mg         = 8,     /* a mail group member (EXPERIMENTAL),[RFC1035], */
      rec_mr         = 9,     /* a mail rename domain name (EXPERIMENTAL),[RFC1035], */
      rec_null       = 10,    /* a null RR (EXPERIMENTAL),[RFC1035], */
      rec_wks        = 11,    /* a well known service description,[RFC1035], */
      rec_ptr        = 12,    /* a domain name pointer,[RFC1035], */
      rec_hinfo      = 13,    /* host information,[RFC1035], */
      rec_minfo      = 14,    /* mailbox or mail list information,[RFC1035], */
      rec_mx         = 15,    /* mail exchange,[RFC1035], */
      rec_txt        = 16,    /* text strings,[RFC1035], */
      rec_rp         = 17,    /* for Responsible Person,[RFC1183], */
      rec_afsdb      = 18,    /* for AFS Data Base location,[RFC1183][RFC5864], */
      rec_x25        = 19,    /* for X.25 PSDN address,[RFC1183], */
      rec_isdn       = 20,    /* for ISDN address,[RFC1183], */
      rec_rt         = 21,    /* for Route Through,[RFC1183], */
      rec_nsap       = 22,    /* for NSAP address, NSAP style A record,[RFC1706], */
      rec_nsap_ptr   = 23,    /* for domain name pointer, NSAP style,[RFC1348][RFC1637][RFC1706], */
      rec_sig        = 24,    /* for security signature,[RFC4034][RFC3755][RFC2535][RFC2536][RFC2537][RFC2931][RFC3110][RFC3008], */
      rec_key        = 25,    /* for security key,[RFC4034][RFC3755][RFC2535][RFC2536][RFC2537][RFC2539][RFC3008][RFC3110], */
      rec_px         = 26,    /* X.400 mail mapping information,[RFC2163], */
      rec_gpos       = 27,    /* Geographical Position,[RFC1712], */
      rec_aaaa       = 28,    /* IP6 Address,[RFC3596], */
      rec_loc        = 29,    /* Location Information,[RFC1876], */
      rec_nxt        = 30,    /* Next Domain (OBSOLETE),[RFC3755][RFC2535], */
      rec_eid        = 31,    /* Endpoint Identifier,[Michael_Patton][http://ana-3.lcs.mit.edu/~jnc/nimrod/dns.txt],1995-06 */
      rec_nimloc     = 32,    /* Nimrod Locator,[1][Michael_Patton][http://ana-3.lcs.mit.edu/~jnc/nimrod/dns.txt],1995-06 */
      rec_srv        = 33,    /* Server Selection,[1][RFC2782], */
      rec_atma       = 34,    /* ATM Address,"[ATM Forum Technical Committee, ""ATM Name System, V2.0"", Doc ID: AF-DANS-0152.000, July 2000. Available from and held in escrow by IANA.]", */
      rec_naptr      = 35,    /* Naming Authority Pointer,[RFC2915][RFC2168][RFC3403], */
      rec_kx         = 36,    /* Key Exchanger,[RFC2230], */
      rec_cert       = 37,    /* CERT,[RFC4398], */
      rec_a6         = 38,    /* A6 (OBSOLETE - use AAAA),[RFC3226][RFC2874][RFC6563], */
      rec_dname      = 39,    /* DNAME,[RFC6672], */
      rec_sink       = 40,    /* SINK,[Donald_E_Eastlake][http://tools.ietf.org/html/draft-eastlake-kitchen-sink],1997-11 */
      rec_opt        = 41,    /* OPT,[RFC6891][RFC3225], */
      rec_apl        = 42,    /* APL,[RFC3123], */
      rec_ds         = 43,    /* Delegation Signer,[RFC4034][RFC3658], */
      rec_sshfp      = 44,    /* SSH Key Fingerprint,[RFC4255], */
      rec_ipseckey   = 45,    /* IPSECKEY,[RFC4025], */
      rec_rrsig      = 46,    /* RRSIG,[RFC4034][RFC3755], */
      rec_nsec       = 47,    /* NSEC,[RFC4034][RFC3755], */
      rec_dnskey     = 48,    /* DNSKEY,[RFC4034][RFC3755], */
      rec_dhcid      = 49,    /* DHCID,[RFC4701], */
      rec_nsec3      = 50,    /* NSEC3,[RFC5155], */
      rec_nsec3param = 51,    /* NSEC3PARAM,[RFC5155], */
      rec_tlsa       = 52,    /* TLSA,[RFC6698], */
      rec_smimea     = 53,    /* S/MIME cert association,[draft-ietf-dane-smime],SMIMEA/smimea-completed-template,2015-12-01 */
      rec_hip        = 55,    /* Host Identity Protocol,[RFC5205], */
      rec_ninfo      = 56,    /* NINFO,[Jim_Reid],NINFO/ninfo-completed-template,2008-01-21 */
      rec_rkey       = 57,    /* RKEY,[Jim_Reid],RKEY/rkey-completed-template,2008-01-21 */
      rec_talink     = 58,    /* Trust Anchor LINK,[Wouter_Wijngaards],TALINK/talink-completed-template,2010-02-17 */
      rec_cds        = 59,    /* Child DS,[RFC7344],CDS/cds-completed-template,2011-06-06 */
      rec_cdnskey    = 60,    /* DNSKEY(s) the Child wants reflected in DS,[RFC7344],2014-06-16 */
      rec_openpgpkey = 61,    /* OpenPGP Key,[RFC-ietf-dane-openpgpkey-12],OPENPGPKEY/openpgpkey-completed-template,2014-08-12 */
      rec_csync      = 62,    /* Child-To-Parent Synchronization,[RFC7477],2015-01-27 */
      rec_spf        = 99,    /* [RFC7208], */
      rec_uinfo      = 100,   /* [IANA-Reserved], */
      rec_uid        = 101,   /* [IANA-Reserved], */
      rec_gid        = 102,   /* [IANA-Reserved], */
      rec_unspec     = 103,   /* [IANA-Reserved], */
      rec_nid        = 104,   /* [RFC6742],ILNP/nid-completed-template, */
      rec_l32        = 105,   /* [RFC6742],ILNP/l32-completed-template, */
      rec_l64        = 106,   /* [RFC6742],ILNP/l64-completed-template, */
      rec_lp         = 107,   /* [RFC6742],ILNP/lp-completed-template, */
      rec_eui48      = 108,   /* an EUI-48 address,[RFC7043],EUI48/eui48-completed-template,2013-03-27 */
      rec_eui64      = 109,   /* an EUI-64 address,[RFC7043],EUI64/eui64-completed-template,2013-03-27 */
      rec_tkey       = 249,   /* Transaction Key,[RFC2930], */
      rec_tsig       = 250,   /* Transaction Signature,[RFC2845], */
      rec_ixfr       = 251,   /* incremental transfer,[RFC1995], */
      rec_axfr       = 252,   /* transfer of an entire zone,[RFC1035][RFC5936], */
      rec_mailb      = 253,   /* mailbox-related RRs (MB, MG or MR),[RFC1035], */
      rec_maila      = 254,   /* mail agent RRs (OBSOLETE - see MX),[RFC1035], */
      rec_any        = 255,   /* A request for all records the server/cache has available,[RFC1035][RFC6895], */
      rec_uri        = 256,   /* URI,[RFC7553],URI/uri-completed-template,2011-02-22 */
      rec_caa        = 257,   /* Certification Authority Restriction,[RFC6844],CAA/caa-completed-template,2011-04-07 */
      rec_avc        = 258,   /* Application Visibility and Control,[Wolfgang_Riedel],AVC/avc-completed-template,2016-02-26 */
      rec_ta         = 32768, /* DNSSEC Trust Authorities,[Sam_Weiler][http://cameo.library.cmu.edu/][Deploying DNSSEC Without a Signed Root. Technical Report 1999-19,Information Networking Institute, Carnegie Mellon University, April 2004.],2005-12-13 */
      rec_dlv        = 32769, /* DNSSEC Lookaside Validation,[RFC4431], */

      /* unassigned = 54, */
      /* unassigned = 63-98, */
      /* unassigned = 110-248, */
      /* unassigned = 259-32767, */
      /* unassigned = 32770-65279, */
      /* private = 65280-65534, */
      /* reserved = 65535, */
   };

   std::ostream& operator<<(std::ostream& os, rr_type_t rhs)
   {
      switch(rhs)
      {
         case rr_type_t::rec_a:
            return os << "a";
         case rr_type_t::rec_ns:
            return os << "ns";
         case rr_type_t::rec_md:
            return os << "md";
         case rr_type_t::rec_mf:
            return os << "mf";
         case rr_type_t::rec_cname:
            return os << "cname";
         case rr_type_t::rec_soa:
            return os << "soa";
         case rr_type_t::rec_mb:
            return os << "mb";
         case rr_type_t::rec_mg:
            return os << "mg";
         case rr_type_t::rec_mr:
            return os << "mr";
         case rr_type_t::rec_null:
            return os << "null";
         case rr_type_t::rec_wks:
            return os << "wks";
         case rr_type_t::rec_ptr:
            return os << "ptr";
         case rr_type_t::rec_hinfo:
            return os << "hinfo";
         case rr_type_t::rec_minfo:
            return os << "minfo";
         case rr_type_t::rec_mx:
            return os << "mx";
         case rr_type_t::rec_txt:
            return os << "txt";
         case rr_type_t::rec_rp:
            return os << "rp";
         case rr_type_t::rec_afsdb:
            return os << "afsdb";
         case rr_type_t::rec_x25:
            return os << "x25";
         case rr_type_t::rec_isdn:
            return os << "isdn";
         case rr_type_t::rec_rt:
            return os << "rt";
         case rr_type_t::rec_nsap:
            return os << "nsap";
         case rr_type_t::rec_nsap_ptr:
            return os << "nsap_ptr";
         case rr_type_t::rec_sig:
            return os << "sig";
         case rr_type_t::rec_key:
            return os << "key";
         case rr_type_t::rec_px:
            return os << "px";
         case rr_type_t::rec_gpos:
            return os << "gpos";
         case rr_type_t::rec_aaaa:
            return os << "aaaa";
         case rr_type_t::rec_loc:
            return os << "loc";
         case rr_type_t::rec_nxt:
            return os << "nxt";
         case rr_type_t::rec_eid:
            return os << "eid";
         case rr_type_t::rec_nimloc:
            return os << "nimloc";
         case rr_type_t::rec_srv:
            return os << "srv";
         case rr_type_t::rec_atma:
            return os << "atma";
         case rr_type_t::rec_naptr:
            return os << "naptr";
         case rr_type_t::rec_kx:
            return os << "kx";
         case rr_type_t::rec_cert:
            return os << "cert";
         case rr_type_t::rec_a6:
            return os << "a6";
         case rr_type_t::rec_dname:
            return os << "dname";
         case rr_type_t::rec_sink:
            return os << "sink";
         case rr_type_t::rec_opt:
            return os << "opt";
         case rr_type_t::rec_apl:
            return os << "apl";
         case rr_type_t::rec_ds:
            return os << "ds";
         case rr_type_t::rec_sshfp:
            return os << "sshfp";
         case rr_type_t::rec_ipseckey:
            return os << "ipseckey";
         case rr_type_t::rec_rrsig:
            return os << "rrsig";
         case rr_type_t::rec_nsec:
            return os << "nsec";
         case rr_type_t::rec_dnskey:
            return os << "dnskey";
         case rr_type_t::rec_dhcid:
            return os << "dhcid";
         case rr_type_t::rec_nsec3:
            return os << "nsec3";
         case rr_type_t::rec_nsec3param:
            return os << "nsec3param";
         case rr_type_t::rec_tlsa:
            return os << "tlsa";
         case rr_type_t::rec_smimea:
            return os << "smimea";
         case rr_type_t::rec_hip:
            return os << "hip";
         case rr_type_t::rec_ninfo:
            return os << "ninfo";
         case rr_type_t::rec_rkey:
            return os << "rkey";
         case rr_type_t::rec_talink:
            return os << "talink";
         case rr_type_t::rec_cds:
            return os << "cds";
         case rr_type_t::rec_cdnskey:
            return os << "cdnskey";
         case rr_type_t::rec_openpgpkey:
            return os << "openpgpkey";
         case rr_type_t::rec_csync:
            return os << "csync";
         case rr_type_t::rec_spf:
            return os << "spf";
         case rr_type_t::rec_uinfo:
            return os << "uinfo";
         case rr_type_t::rec_uid:
            return os << "uid";
         case rr_type_t::rec_gid:
            return os << "gid";
         case rr_type_t::rec_unspec:
            return os << "unspec";
         case rr_type_t::rec_nid:
            return os << "nid";
         case rr_type_t::rec_l32:
            return os << "l32";
         case rr_type_t::rec_l64:
            return os << "l64";
         case rr_type_t::rec_lp:
            return os << "lp";
         case rr_type_t::rec_eui48:
            return os << "eui48";
         case rr_type_t::rec_eui64:
            return os << "eui64";
         case rr_type_t::rec_tkey:
            return os << "tkey";
         case rr_type_t::rec_tsig:
            return os << "tsig";
         case rr_type_t::rec_ixfr:
            return os << "ixfr";
         case rr_type_t::rec_axfr:
            return os << "axfr";
         case rr_type_t::rec_mailb:
            return os << "mailb";
         case rr_type_t::rec_maila:
            return os << "maila";
         case rr_type_t::rec_any:
            return os << "any";
         case rr_type_t::rec_uri:
            return os << "uri";
         case rr_type_t::rec_caa:
            return os << "caa";
         case rr_type_t::rec_avc:
            return os << "avc";
         case rr_type_t::rec_ta:
            return os << "ta";
         case rr_type_t::rec_dlv:
            return os << "dlv";
      }

      return os << static_cast<unsigned>(rhs);
   }
}
