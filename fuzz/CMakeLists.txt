include_directories(${CMAKE_SOURCE_DIR}/paxos/include)
include_directories(${CMAKE_SOURCE_DIR}/evpaxos/include)
include_directories(${CMAKE_SOURCE_DIR}/fuzz/include)
include_directories(${LIBEVENT_INCLUDE_DIRS})

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
set(FUZZ_SOURCES oracle.c gremlin.c)

add_library(fuzzing SHARED ${FUZZ_SOURCES})
target_link_libraries(fuzzing evpaxos dl ${LIBPAXOS_LINKER_LIBS} ${LIBEVENT_LIBRARIES}
	${MSGPACK_LIBRARIES} Threads::Threads)

set(FUZZ_DRIVERS test-oracle.c)

foreach(p ${FUZZ_DRIVERS})
    get_filename_component(target "${p}" NAME_WE)
    add_executable(${target} ${p})
    target_link_libraries(${target} evpaxos fuzzing ${LIBPAXOS_LINKER_LIBS})
endforeach(p)


