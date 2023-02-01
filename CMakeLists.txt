cmake_minimum_required(VERSION 3.10)

project(sha-256)

function(cpp17 target)
    set_target_properties(${target}
        PROPERTIES
            CXX_STANDARD 17
            CXX_STANDARD_REQUIRED ON
            CXX_EXTENSIONS OFF
    )

    target_compile_options(${target}
        PRIVATE
            -Wall -Wextra -Wconversion -pedantic -Wno-sign-conversion
    )
endfunction()

add_library(sha256 STATIC src/sha256.cpp)
cpp17(sha256)
target_include_directories(sha256 PUBLIC include)

add_executable(sha256sum examples/sha256sum.cpp)
cpp17(sha256sum)
target_link_libraries(sha256sum sha256)
