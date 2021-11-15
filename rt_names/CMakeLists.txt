add_library(Rt_Names src/rt_names.c)

list(APPEND EXTRA_INCLUDE_DIRECTORIES "${CMAKE_CURRENT_SOURCE_DIR}/includes")
list(APPEND EXTRA_INCLUDE_DIRECTORIES "${CMAKE_CURRENT_SOURCE_DIR}/../libnetlink/includes")

target_include_directories(Rt_Names
        PUBLIC ${EXTRA_INCLUDE_DIRECTORIES}
        )