find_program(_CLANG_FORMAT clang-format)
set(CLANG_FORMAT "${_CLANG_FORMAT}" CACHE STRING "clang-format executable")
if(CLANG_FORMAT)
    message(STATUS "Found clang-format: ${CLANG_FORMAT}")
endif()
function(clang_format TGT)
    if(CLANG_FORMAT)
        add_custom_target(${TGT})
        foreach(_DIR ${ARGN})
            file(GLOB_RECURSE _FILES
                "${_DIR}/*.hpp"
                "${_DIR}/*.hpp.in"
                "${_DIR}/*.cpp"
            )
            foreach(_FILE ${_FILES})
                file(RELATIVE_PATH _FNAME "${PROJECT_SOURCE_DIR}" ${_FILE})
                add_custom_command(TARGET ${TGT} PRE_BUILD
                    COMMAND "${CLANG_FORMAT}" -i -style=file "${_FILE}"
                    COMMENT "clang-format: ${_FNAME}"
                )
            endforeach()
        endforeach()
    endif()
endfunction()
