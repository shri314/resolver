cmake_minimum_required (VERSION 3.5)
project (libdns)
enable_testing()

add_compile_options("-std=c++1z")
add_compile_options("-g3")
include_directories("include")

set(mydig_LIBS
      boost_system
      boost_thread
      pthread
   )
set(mydig_SOURCES "src/MyDns.cpp")

add_executable(mydig ${mydig_SOURCES})
target_link_libraries(mydig ${mydig_LIBS})

add_subdirectory(test EXCLUDE_FROM_ALL)
