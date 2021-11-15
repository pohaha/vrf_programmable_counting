add_library(Libnetlink src/libnetlink.c)

list(APPEND EXTRA_INCLUDE_DIRECTORIES "${CMAKE_CURRENT_SOURCE_DIR}/includes")
list(APPEND EXTRA_INCLUDE_DIRECTORIES "${CMAKE_CURRENT_SOURCE_DIR}/../rt_names/includes")
list(APPEND EXTRA_LINKED_SOURCES Rt_Names)


target_include_directories(Libnetlink
        PUBLIC ${EXTRA_INCLUDE_DIRECTORIES}
        )
target_link_libraries(Libnetlink
        ${EXTRA_LINKED_SOURCES}
        )