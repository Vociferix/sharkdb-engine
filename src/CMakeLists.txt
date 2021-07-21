capnp_generate_cpp(SHARKDB_SOURCES SHARKDB_HEADERS sharkdb.capnp)
add_executable(sharkdb-engine
    ${SHARKDB_HEADERS}

    ${SHARKDB_SOURCES}
    main.cpp
)
target_link_libraries(sharkdb-engine PRIVATE CapnProto::capnp Wireshark)
target_include_directories(sharkdb-engine PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")
