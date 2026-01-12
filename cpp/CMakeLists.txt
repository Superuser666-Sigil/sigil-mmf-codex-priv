cmake_minimum_required(VERSION 3.25)
project(sigil-mmf-cpp VERSION 1.0.0 LANGUAGES CXX)

# Require C++23
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Export compile commands for IDEs
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Compiler flags
if(MSVC)
    add_compile_options(/W4 /WX)
else()
    add_compile_options(-Wall -Wextra -Wpedantic -Werror)
endif()

# Find dependencies
find_package(PkgConfig REQUIRED)

# nlohmann_json - try multiple ways to find it
find_package(nlohmann_json 3.11 QUIET)
if(NOT nlohmann_json_FOUND)
    # Try pkg-config
    pkg_check_modules(nlohmann_json QUIET nlohmann_json)
    if(nlohmann_json_FOUND)
        message(STATUS \"Found nlohmann_json via pkg-config\")
    else()
        # Try finding the header directly
        find_path(NLOHMANN_JSON_INCLUDE_DIR nlohmann/json.hpp
            PATHS /usr/include /usr/local/include)
        if(NLOHMANN_JSON_INCLUDE_DIR)
            message(STATUS \"Found nlohmann_json headers at ${NLOHMANN_JSON_INCLUDE_DIR}\")
            set(nlohmann_json_FOUND TRUE)
            include_directories(${NLOHMANN_JSON_INCLUDE_DIR})
        else()
            message(FATAL_ERROR \"nlohmann_json not found - required for JSON operations\")
        endif()
    endif()
else()
    message(STATUS \"Found nlohmann_json ${nlohmann_json_VERSION}\")
endif()

# Boost (required for HTTP server)
find_package(Boost 1.82 REQUIRED COMPONENTS system thread)
message(STATUS "Boost found: ${Boost_VERSION}")

find_package(CLI11 2.3)
if(CLI11_FOUND)
    message(STATUS \"CLI11 found\")
else()
    message(WARNING \"CLI11 not found - CLI features will be disabled\")
endif()

# libsodium
pkg_check_modules(SODIUM REQUIRED libsodium>=1.0.18)

# RocksDB (optional for now)
find_path(ROCKSDB_INCLUDE_DIR rocksdb/db.h)
find_library(ROCKSDB_LIBRARY rocksdb)
if(ROCKSDB_INCLUDE_DIR AND ROCKSDB_LIBRARY)
    message(STATUS \"RocksDB found\")
    set(HAVE_ROCKSDB TRUE)
else()
    message(WARNING \"RocksDB not found - storage features will be disabled\")
    set(HAVE_ROCKSDB FALSE)
endif()

# toml++ (optional for now)
find_path(TOMLPLUSPLUS_INCLUDE_DIR toml++/toml.h)
if(TOMLPLUSPLUS_INCLUDE_DIR)
    message(STATUS \"toml++ found\")
    set(HAVE_TOMLPP TRUE)
else()
    message(WARNING \"toml++ not found - config features will be disabled\")
    set(HAVE_TOMLPP FALSE)
endif()

# spdlog (optional for now)
find_package(spdlog)
if(spdlog_FOUND)
    message(STATUS \"spdlog found\")
    set(HAVE_SPDLOG TRUE)
else()
    message(WARNING \"spdlog not found - advanced logging will be disabled\")
    set(HAVE_SPDLOG FALSE)
endif()

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${SODIUM_INCLUDE_DIRS}
)

if(HAVE_ROCKSDB)
    include_directories(${ROCKSDB_INCLUDE_DIR})
endif()

if(HAVE_TOMLPP)
    include_directories(${TOMLPLUSPLUS_INCLUDE_DIR})
endif()

# Source files
set(SIGIL_SOURCES
    src/crypto.cpp
    src/json_canonicalization.cpp
    src/types.cpp
    src/canonical_record.cpp
    src/config.cpp
    src/audit.cpp
    src/canon_store.cpp
    src/license_validator.cpp
    src/trust_linear.cpp
    src/loa_policy.cpp
    src/witness_registry.cpp
    src/quorum_system.cpp
    src/rate_limiter.cpp
    src/web_server.cpp
)

# Library
add_library(sigil_core STATIC ${SIGIL_SOURCES})
target_link_libraries(sigil_core
    PUBLIC
        nlohmann_json::nlohmann_json
        ${SODIUM_LIBRARIES}
)

if(HAVE_ROCKSDB)
    target_link_libraries(sigil_core PUBLIC ${ROCKSDB_LIBRARY})
    target_compile_definitions(sigil_core PUBLIC SIGIL_HAVE_ROCKSDB=1)
endif()

target_link_libraries(sigil_core PUBLIC Boost::system Boost::thread)
target_compile_definitions(sigil_core PUBLIC SIGIL_HAVE_BOOST=1)

if(HAVE_SPDLOG)
    target_link_libraries(sigil_core PUBLIC spdlog::spdlog)
    target_compile_definitions(sigil_core PUBLIC SIGIL_HAVE_SPDLOG=1)
endif()

if(HAVE_TOMLPP)
    target_compile_definitions(sigil_core PUBLIC SIGIL_HAVE_TOMLPP=1)
endif()

if(CLI11_FOUND)
    target_compile_definitions(sigil_core PUBLIC SIGIL_HAVE_CLI11=1)
endif()

target_include_directories(sigil_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

# Main executable (optional - only if CLI11 is available)
if(CLI11_FOUND)
    add_executable(sigil src/main.cpp)
    target_link_libraries(sigil PRIVATE sigil_core CLI11::CLI11)
    install(TARGETS sigil DESTINATION bin)
    message(STATUS "Building main executable with CLI support")
else()
    message(STATUS "Skipping main executable (CLI11 not found)")
endif()

# Tests
enable_testing()
add_subdirectory(tests)
install(DIRECTORY include/ DESTINATION include)
