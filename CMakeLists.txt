cmake_minimum_required(VERSION 3.10)

project(DoloyRKN)

set(CMAKE_CXX_STANDARD 26)
set(CMAKE_CXX_STANDARD_REQUIRED True)

file(GLOB_RECURSE INIT_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/init/*)
file(GLOB_RECURSE CORE_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/core/*.cpp)
file(GLOB_RECURSE PACKET_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/packet/*.cpp)
file(GLOB_RECURSE CIRCUMVENTION_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/circumvention/*.cpp)
file(GLOB_RECURSE CLI_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/cli/*.cpp)
file(GLOB_RECURSE UTIL_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/util/*.cpp)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    file(GLOB_RECURSE PLATFORM_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/platform/linux/*.cpp)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    file(GLOB_RECURSE PLATFORM_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/platform/windows/*.cpp)
    file(GLOB RESOURCES_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/platform/windows/resource/resource.rc)
endif()

set(PROJECT_FILES
${INIT_SRC} 
${CORE_SRC} 
${PACKET_SRC} 
${CIRCUMVENTION_SRC} 
${CLI_SRC} 
${UTIL_SRC} 
${PLATFORM_SRC}
${RESOURCES_SRC})

add_executable(${PROJECT_NAME} ${PROJECT_FILES})

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src ${CMAKE_CURRENT_SOURCE_DIR}/third_party/libnetfilter_queue/include)
    target_link_libraries(${PROJECT_NAME} PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/third_party/libnetfilter_queue/lib/libnetfilter_queue.a"
    "${CMAKE_CURRENT_SOURCE_DIR}/third_party/libnfnetlink/lib/libnfnetlink.a"
    "${CMAKE_CURRENT_SOURCE_DIR}/third_party/libmnl/lib/libmnl.a")

    target_link_options(${PROJECT_NAME} PRIVATE -static-libgcc -static-libstdc++ -static)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src ${CMAKE_CURRENT_SOURCE_DIR}/third_party/WinDivert)

    add_library(WinDivert SHARED IMPORTED)

    set_target_properties(WinDivert PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_CURRENT_SOURCE_DIR}/third_party/WinDivert/include"
    IMPORTED_IMPLIB "${CMAKE_CURRENT_SOURCE_DIR}/third_party/WinDivert/lib/WinDivert.lib"
    IMPORTED_LOCATION "${CMAKE_CURRENT_SOURCE_DIR}/third_party/WinDivert/lib/WinDivert.dll")

    target_link_libraries(${PROJECT_NAME} PRIVATE WinDivert)
    target_link_options(${PROJECT_NAME} PRIVATE -static)

    add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CMAKE_CURRENT_SOURCE_DIR}/third_party/WinDivert/lib/WinDivert.dll"
            $<TARGET_FILE_DIR:${PROJECT_NAME}>
    )

    add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CMAKE_CURRENT_SOURCE_DIR}/third_party/WinDivert/lib/WinDivert64.sys"
            $<TARGET_FILE_DIR:${PROJECT_NAME}>
    )
endif()

if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_compile_options(${PROJECT_NAME} PRIVATE
    -flto
    -O3
    -fno-common
    -fdiagnostics-show-option
    -Wall
    -Wextra
    -pedantic
    -pedantic-errors
    -Wshadow
    -Wnon-virtual-dtor
    -Wcast-qual
    -Wcast-align
    -Wsign-conversion
    -Wfloat-equal
    -Wlogical-op
    -Wmisleading-indentation
    -Wnull-dereference
    -Wold-style-cast
    -Woverloaded-virtual
    -Wredundant-decls
    -Wswitch-default
    -Wswitch-enum
    -Wunused-parameter
    -Wunused-variable
    -Wunused-function
    -Wunused-result
    -Wunused-but-set-variable
    -Wunused-const-variable
    -Wdouble-promotion
    -Wformat=2
    -Winit-self
    -Wmissing-include-dirs
    -Wplacement-new=2
    -Wpointer-arith
    -Wredundant-move
    -Wstrict-aliasing=2
    -Wsuggest-final-methods
    -Wsuggest-final-types
    -Wsuggest-override
    -Wundef
    -Wuninitialized
    -Wunknown-pragmas
    -Wuseless-cast)
elseif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    target_compile_options(${PROJECT_NAME} PRIVATE -Wall -Werror)
endif()

