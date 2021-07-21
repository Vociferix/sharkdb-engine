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

add_library(Wireshark INTERFACE)
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
target_include_directories(Wireshark INTERFACE "${CMAKE_CURRENT_SOURCE_DIR}/wireshark")
add_dependencies(Wireshark wireshark)
