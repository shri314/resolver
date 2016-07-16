add_test(NAME header_test COMMAND header_test)
add_executable(header_test header_test.cpp)
target_link_libraries(header_test "boost_unit_test_framework")

add_test(NAME label_list_test COMMAND label_list_test)
add_executable(label_list_test label_list_test.cpp)
target_link_libraries(label_list_test "boost_unit_test_framework")

add_test(NAME question_test COMMAND question_test)
add_executable(question_test question_test.cpp)
target_link_libraries(question_test "boost_unit_test_framework")

add_test(NAME record_test COMMAND record_test)
add_executable(record_test record_test.cpp)
target_link_libraries(record_test "boost_unit_test_framework")
