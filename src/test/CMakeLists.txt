add_test(NAME test_header COMMAND test_header)
add_executable(test_header header_test.cpp)
target_link_libraries(test_header "boost_unit_test_framework")

add_test(NAME test_label_list COMMAND test_label_list)
add_executable(test_label_list label_list_test.cpp)
target_link_libraries(test_label_list "boost_unit_test_framework")
