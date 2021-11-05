set(INCLUDE_DIR "${PROJECT_SOURCE_DIR}/include/sharkdb")
set(CAPNPC_SRC_PREFIX "${INCLUDE_DIR}")
capnp_generate_cpp(SHARKDB_SOURCES SHARKDB_HEADERS
    "${INCLUDE_DIR}/file_io.capnp"
    "${INCLUDE_DIR}/pref_info.capnp"
    "${INCLUDE_DIR}/proto_info.capnp"
    "${INCLUDE_DIR}/decode_as_info.capnp"
    "${INCLUDE_DIR}/file_type_info.capnp"
    "${INCLUDE_DIR}/encap_info.capnp"
    "${INCLUDE_DIR}/dissect.capnp"
)
add_executable(sharkdb-engine
    ${SHARKDB_HEADERS}
    read.hpp
    write.hpp
    pref_info.hpp
    proto_info.hpp
    decode_as_info.hpp
    file_type_info.hpp
    encap_info.hpp
    dissect.hpp

    ${SHARKDB_SOURCES}
    main.cpp
    read.cpp
    write.cpp
    pref_info.cpp
    proto_info.cpp
    decode_as_info.cpp
    file_type_info.cpp
    encap_info.cpp
    dissect.cpp
)
target_link_libraries(sharkdb-engine PRIVATE CapnProto::capnp Wireshark)
target_include_directories(sharkdb-engine PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")
