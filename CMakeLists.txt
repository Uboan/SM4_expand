
cmake_minimum_required(VERSION 2.8)

PROJECT(sm4_256)

INCLUDE_DIRECTORIES(include)
INCLUDE_DIRECTORIES(/usr/local/include/)

AUX_SOURCE_DIRECTORY(src DIR_SRCS)

add_library(LIB ${DIR_SRCS})



SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99 -O2")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fopenmp") 


add_executable(TGCM test/TEST_gcm.c)
add_executable(TCTR test/TEST_ctr.c)
add_executable(TSM4CBC test/test_sm4_cbc.c)
add_executable(TSM4EXPAND test/test_sm4_expand.c)
add_executable(T3DESCTR test/TEST_3DES_CTR.c)
add_executable(T3DESCBC test/TEST_3DES_CBC.c)
add_executable(TDESXCTR test/TEST_DESX_CTR.c)
add_executable(TDESXCBC test/TEST_DESX_CBC.c)

target_link_libraries(TGCM LIB "-O2")
target_link_libraries(TCTR LIB "-O2" )
target_link_libraries(TSM4CBC LIB "-O2")
target_link_libraries(TSM4EXPAND LIB "-O2")
target_link_libraries(T3DESCTR LIB "-O2")
target_link_libraries(T3DESCBC LIB "-O2")
target_link_libraries(TDESXCTR LIB "-O2")
target_link_libraries(TDESXCBC LIB "-O2")

