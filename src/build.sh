#!/bin/bash

set -e

g++ -std=c++1z -g3 -o mydig      MyDns.cpp      -lboost_system -lboost_thread -lpthread
#g++ -std=c++1z -g3 -o mydig      Dns.cpp       -lboost_system -lboost_thread -lpthread
#g++ -std=c++1z -g3 -o test_Dns   Dns_test.cpp  -lboost_unit_test_framework
