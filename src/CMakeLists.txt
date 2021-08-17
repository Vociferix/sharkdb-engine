capnp_generate_cpp(SHARKDB_SOURCES SHARKDB_HEADERS
    sharkdb_read.capnp
    sharkdb_pref_info.capnp
    sharkdb_proto_info.capnp
)
add_executable(sharkdb-engine
    ${SHARKDB_HEADERS}
    read.hpp
    pref_info.hpp
    proto_info.hpp

    ${SHARKDB_SOURCES}
    main.cpp
    read.cpp
    pref_info.cpp
    proto_info.cpp
)
target_link_libraries(sharkdb-engine PRIVATE CapnProto::capnp Wireshark)
target_include_directories(sharkdb-engine PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")
