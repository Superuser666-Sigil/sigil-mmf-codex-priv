# Download Catch2 if not found
find_package(Catch2 3 QUIET)
if(NOT Catch2_FOUND)
    include(FetchContent)
    FetchContent_Declare(
        Catch2
        GIT_REPOSITORY https://github.com/catchorg/Catch2.git
        GIT_TAG v3.5.2
    )
    FetchContent_MakeAvailable(Catch2)
    list(APPEND CMAKE_MODULE_PATH ${catch2_SOURCE_DIR}/extras)
endif()

include(CTest)
include(Catch)

# Test executable
# Some test sources may be optional (e.g., policy-specific tests). Only add files that exist.
set(SIGIL_TEST_SOURCES
    test_main.cpp
    test_crypto.cpp
    test_json_canonicalization.cpp
    test_canonical_record.cpp
    test_license_validator.cpp
    test_loa.cpp
    test_loa_policy.cpp
    test_trust_linear.cpp
    test_witness_registry.cpp
    test_rate_limiter.cpp
)

set(SIGIL_TEST_SOURCES_EXISTING)
foreach(_src IN LISTS SIGIL_TEST_SOURCES)
    # Use absolute paths so CMake can't get confused about the working directory.
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${_src}")
        list(APPEND SIGIL_TEST_SOURCES_EXISTING "${CMAKE_CURRENT_SOURCE_DIR}/${_src}")
    endif()
endforeach()

# Ensure we didn't accidentally keep an empty list element
list(REMOVE_ITEM SIGIL_TEST_SOURCES_EXISTING "")

# Warn if no test sources are found
if(NOT SIGIL_TEST_SOURCES_EXISTING)
    message(FATAL_ERROR "No test sources found; check test file paths.")
endif()

# Use only the existing sources when creating the test target
add_executable(sigil_tests ${SIGIL_TEST_SOURCES_EXISTING})

target_link_libraries(sigil_tests PRIVATE sigil_core Catch2::Catch2WithMain)

catch_discover_tests(sigil_tests)
