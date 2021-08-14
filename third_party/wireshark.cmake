include(ExternalProject)

ExternalProject_Add(wireshark
    SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/wireshark"
    CMAKE_GENERATOR "${CMAKE_GENERATOR}"
    CMAKE_ARGS
        -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
        -DENABLE_STATIC=ON
        -DBUILD_sshdump=OFF
        -DBUILD_ciscodump=OFF
        -DBUILD_wireshark=OFF
        -DBUILD_sharkd=OFF
        -DBUILD_tshark=OFF
        -DBUILD_tfshark=OFF
        -DBUILD_rawshark=OFF
        -DBUILD_dftest=OFF
        -DBUILD_randpkt=OFF
        -DBUILD_fuzzshark=OFF
        -DBUILD_text2pcap=OFF
        -DBUILD_mergecap=OFF
        -DBUILD_reordercap=OFF
        -DBUILD_capinfos=OFF
        -DBUILD_captype=OFF
        -DBUILD_editcap=OFF
        -DBUILD_dumpcap=OFF
        -DBUILD_dcerpcidl2wrs=OFF
    BINARY_DIR "${CMAKE_CURRENT_BINARY_DIR}/wireshark"
    BUILD_COMMAND ${CMAKE_COMMAND} --build . --config $<CONFIG> --target epan
    INSTALL_COMMAND ""
)

list(APPEND CMAKE_MODULE_PATH
    "${CMAKE_CURRENT_SOURCE_DIR}/wireshark/cmake/modules"
)

find_package(GLIB2 "2.32.0" REQUIRED)
find_package(GMODULE2)
find_package(GTHREAD2)
find_package(GCRYPT "1.4.2" REQUIRED)
find_package(ZLIB)
find_package(GNUTLS "3.2.0")
find_package(ZSTD "1.0.0")
find_package(LZ4)
find_package(NGHTTP2)
find_package(LibXml2)
find_package(CARES)

add_library(Wireshark INTERFACE)
target_link_libraries(Wireshark INTERFACE
    ${GLIB2_LIBRARIES}
    ${GMODULE2_LIBRARIES}
    ${GTHREAD2_LIBRARIES}
    ${GCRYPT_LIBRARIES}
    ${ZLIB_LIBRARIES}
    ${GNUTLS_LIBRARIES}
    ${ZSTD_LIBRARIES}
    ${LZ4_LIBRARIES}
    ${NGHTTP2_LIBRARIES}
    ${LIBXML2_LIBRARIES}
    ${CARES_LIBRARIES}
)
if(WIN32)
    target_link_libraries(Wireshark INTERFACE
        "${CMAKE_CURRENT_BINARY_DIR}/wireshark/run/libwireshark.lib"
        "${CMAKE_CURRENT_BINARY_DIR}/wireshark/run/libwiretap.lib"
        "${CMAKE_CURRENT_BINARY_DIR}/wireshark/run/libwsutil.lib"
    )
else()
    target_link_libraries(Wireshark INTERFACE
        "${CMAKE_CURRENT_BINARY_DIR}/wireshark/run/libwireshark.a"
        "${CMAKE_CURRENT_BINARY_DIR}/wireshark/run/libwiretap.a"
        "${CMAKE_CURRENT_BINARY_DIR}/wireshark/run/libwsutil.a"
    )
endif()
target_include_directories(Wireshark INTERFACE
    "${CMAKE_CURRENT_SOURCE_DIR}/wireshark"
    "${GLIB2_INCLUDE_DIRS}"
)
add_dependencies(Wireshark wireshark)
