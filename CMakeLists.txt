project(VRF_COUNT C CXX)
CMAKE_MINIMUM_REQUIRED(VERSION 3.12)

set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address")
set (CMAKE_VERBOSE_MAKEFILE ON)

add_library(vrf_count "${CMAKE_CURRENT_SOURCE_DIR}/vrf_counter.cpp" )

add_subdirectory(rt_names)
add_subdirectory(libnetlink)


list(APPEND EXTRA_INCLUDE_DIRECTORIES "${CMAKE_CURRENT_SOURCE_DIR}/rt_names/includes")
list(APPEND EXTRA_LINKED_SOURCES Rt_Names)

list(APPEND EXTRA_INCLUDE_DIRECTORIES "${CMAKE_CURRENT_SOURCE_DIR}/libnetlink/includes")
list(APPEND EXTRA_LINKED_SOURCES Libnetlink)

list(APPEND EXTRA_INCLUDE_DIRECTORIES "${CMAKE_CURRENT_SOURCE_DIR}/includes")




target_include_directories(vrf_count
        PUBLIC ${EXTRA_INCLUDE_DIRECTORIES}
        )

target_link_libraries(vrf_count
        ${EXTRA_LINKED_SOURCES}
        )
