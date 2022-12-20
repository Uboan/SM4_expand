
cmake_minimum_required(VERSION 2.8)

PROJECT(sm4_256)

INCLUDE_DIRECTORIES(include)
INCLUDE_DIRECTORIES(/usr/local/include/)

AUX_SOURCE_DIRECTORY(src DIR_SRCS)

add_library(LIB ${DIR_SRCS})





SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99 -O2")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fopenmp") 

 add_executable(TLM test/test_lai_massey.c)
 add_executable(TEM test/test_even_mansour.c)
 add_executable(TGCM test/TEST_gcm.c)
 add_executable(TCTR test/TEST_ctr.c)
 add_executable(TECB test/TEST_ecb.c)
 
add_executable(TLCBC test/test_LM_cbc.c)
add_executable(TECBC test/test_EM_cbc.c)
add_executable(TSM4CBC test/test_sm4_cbc.c)
add_executable(TLUTEM test/test_LUT_EM.c)
add_executable(TSM4EXPAND test/test_sm4_expand.c)

target_link_libraries(TLM LIB "-O2")
target_link_libraries(TEM LIB "-O2")
target_link_libraries(TGCM LIB "-O2")
target_link_libraries(TCTR LIB "-O2" )
target_link_libraries(TECB LIB "-O2")
target_link_libraries(TLCBC LIB "-O2")
target_link_libraries(TECBC LIB "-O2")
target_link_libraries(TSM4CBC LIB "-O2")
target_link_libraries(TLUTEM LIB "-O2")
target_link_libraries(TSM4EXPAND LIB "-O2")

