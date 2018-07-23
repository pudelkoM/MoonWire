CMAKE_MINIMUM_REQUIRED(VERSION 2.8.10)

SET(CMAKE_CXX_FLAGS "-fno-stack-protector -Wall -Wextra -Wno-unused-parameter -Wno-unused-variable -Wno-unused-function -g -O3 -std=gnu++11 -march=native")
SET(CMAKE_C_FLAGS "-fno-stack-protector -Wall -Wextra -Wno-unused-parameter -Wno-unused-variable -Wno-unused-function -g -O3 -std=gnu11 -march=native")

SET(PRJ moonwire)

SET(SRC src/dpdk-pktmbuf-export.c)

SET(LIBMOON_DIR ${CMAKE_CURRENT_SOURCE_DIR}/libmoon)

INCLUDE_DIRECTORIES(
	${CMAKE_CURRENT_SOURCE_DIR}/src
	${LIBMOON_DIR}/deps/dpdk/x86_64-native-linuxapp-gcc/include
	${LIBMOON_DIR}/deps/luajit/src
	${LIBMOON_DIR}/lib
	${LIBMOON_DIR}/src
)

ADD_LIBRARY(dpdk-pktmbuf-export SHARED ${SRC})

INCLUDE_DIRECTORIES(src/libsodium/build/include)
ADD_EXECUTABLE(sodium-bench benchmarks/libsodium/chacha20_poly1305_ietf.c)
TARGET_LINK_LIBRARIES(sodium-bench ${CMAKE_SOURCE_DIR}/src/libsodium/build/lib/libsodium.a rt)

ADD_LIBRARY(rfc2401 SHARED src/rfc2401.c)
ADD_LIBRARY(rfc6479 SHARED src/rfc6479.c)

ADD_EXECUTABLE(replay-bench benchmarks/sliding-window/bench.c)
TARGET_LINK_LIBRARIES(replay-bench rfc2401 rfc6479 rt)
