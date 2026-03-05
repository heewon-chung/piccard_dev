cmake_minimum_required(VERSION 3.20)
project(piccard-fhe VERSION 0.2.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Compiler flags
set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -Wall -Wextra")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")

# Find OpenFHE (required for FHE operations)
find_package(OpenFHE QUIET)
if(OpenFHE_FOUND)
    message(STATUS "Found OpenFHE: ${BASE_OPENFHE_VERSION}")
    message(STATUS "OpenFHE include: ${OpenFHE_INCLUDE}")
    message(STATUS "OpenFHE libraries: ${OpenFHE_LIBRARIES}")
    add_compile_definitions(HAVE_OPENFHE)
else()
    message(STATUS "OpenFHE not found - FHE features disabled")
endif()

# Include directories
include_directories(${CMAKE_SOURCE_DIR}/include)
if(OpenFHE_FOUND)
    include_directories(
        ${OpenFHE_INCLUDE}
        ${OpenFHE_INCLUDE}/third-party/include
        ${OpenFHE_INCLUDE}/core
        ${OpenFHE_INCLUDE}/pke
        ${OpenFHE_INCLUDE}/binfhe
    )
    link_directories(${OpenFHE_LIBDIR})

    if(OPENMP_LIBRARIES)
        link_directories(${OPENMP_LIBRARIES})
    endif()
endif()

# =============================================================================
# piccard_core: Pure math modules (no OpenFHE dependency)
# =============================================================================

set(PICCARD_CORE_SOURCES
    src/util/params.cpp
    src/core/minhash.cpp
    src/core/onehot_encoder.cpp
    src/core/bottom_structure.cpp
    src/core/threshold_poly.cpp
)

add_library(piccard_core ${PICCARD_CORE_SOURCES})
target_include_directories(piccard_core PUBLIC ${CMAKE_SOURCE_DIR}/include)

# =============================================================================
# piccard_fhe: BFV context + engine (requires OpenFHE)
# =============================================================================

if(OpenFHE_FOUND)
    set(PICCARD_FHE_SOURCES
        src/fhe/bfv_context.cpp
        src/protocol/piccard_engine.cpp
        src/protocol/piccard.cpp
        src/protocol/dynamic_piccard.cpp
        src/protocol/threshold_piccard.cpp
    )

    add_library(piccard_fhe ${PICCARD_FHE_SOURCES})
    target_link_libraries(piccard_fhe
        PUBLIC
            piccard_core
            ${OpenFHE_LIBRARIES}
    )
    target_include_directories(piccard_fhe
        PUBLIC
            ${OpenFHE_INCLUDE}
            ${OpenFHE_INCLUDE}/third-party/include
            ${OpenFHE_INCLUDE}/core
            ${OpenFHE_INCLUDE}/pke
            ${OpenFHE_INCLUDE}/binfhe
    )
    set(HAVE_PICCARD_FHE TRUE)
else()
    set(HAVE_PICCARD_FHE FALSE)
endif()

# =============================================================================
# Tests
# =============================================================================

option(BUILD_TESTS "Build unit and integration tests" ON)

if(BUILD_TESTS)
    enable_testing()
    find_package(GTest QUIET)

    if(GTest_FOUND)
        message(STATUS "Found GTest, building tests")

        # Shared test main with custom property printer
        add_library(test_main STATIC tests/test_main.cpp)
        target_link_libraries(test_main PUBLIC GTest::gtest)

        # Core tests (no OpenFHE needed)
        add_executable(test_params tests/unit/test_params.cpp)
        target_link_libraries(test_params piccard_core test_main)
        add_test(NAME Params COMMAND test_params)

        add_executable(test_minhash tests/unit/test_minhash.cpp)
        target_link_libraries(test_minhash piccard_core test_main)
        add_test(NAME MinHash COMMAND test_minhash)

        add_executable(test_onehot_encoder tests/unit/test_onehot_encoder.cpp)
        target_link_libraries(test_onehot_encoder piccard_core test_main)
        add_test(NAME OneHotEncoder COMMAND test_onehot_encoder)

        add_executable(test_bottom_structure tests/unit/test_bottom_structure.cpp)
        target_link_libraries(test_bottom_structure piccard_core test_main)
        add_test(NAME BottomStructure COMMAND test_bottom_structure)

        add_executable(test_threshold_poly tests/unit/test_threshold_poly.cpp)
        target_link_libraries(test_threshold_poly piccard_core test_main)
        add_test(NAME ThresholdPoly COMMAND test_threshold_poly)

        # FHE tests (require OpenFHE)
        if(OpenFHE_FOUND AND HAVE_PICCARD_FHE)
            add_executable(test_bfv_context tests/unit/test_bfv_context.cpp)
            target_link_libraries(test_bfv_context piccard_fhe test_main)
            add_test(NAME BFVContext COMMAND test_bfv_context)

            add_executable(test_piccard_engine tests/unit/test_piccard_engine.cpp)
            target_link_libraries(test_piccard_engine piccard_fhe test_main)
            add_test(NAME PiccardEngine COMMAND test_piccard_engine)

            add_executable(test_dynamic_engine tests/unit/test_dynamic_engine.cpp)
            target_link_libraries(test_dynamic_engine piccard_fhe test_main)
            add_test(NAME DynamicEngine COMMAND test_dynamic_engine)

            add_executable(test_threshold_engine tests/unit/test_threshold_engine.cpp)
            target_link_libraries(test_threshold_engine piccard_fhe test_main)
            add_test(NAME ThresholdEngine COMMAND test_threshold_engine)

            # Integration test
            add_executable(test_piccard_e2e tests/integration/test_piccard_e2e.cpp)
            target_link_libraries(test_piccard_e2e piccard_fhe test_main)
            add_test(NAME PiccardE2E COMMAND test_piccard_e2e)
        endif()
    else()
        message(STATUS "GTest not found, skipping tests")
    endif()
endif()

# =============================================================================
# Benchmarks
# =============================================================================

option(BUILD_BENCHMARKS "Build benchmark executables" ON)

if(BUILD_BENCHMARKS AND OpenFHE_FOUND AND HAVE_PICCARD_FHE)
    add_executable(bench_piccard benchmarks/bench_piccard.cpp)
    target_link_libraries(bench_piccard piccard_fhe)
    target_include_directories(bench_piccard PRIVATE ${CMAKE_SOURCE_DIR}/benchmarks)

    add_executable(bench_comparison benchmarks/bench_comparison.cpp)
    target_link_libraries(bench_comparison piccard_fhe)
    target_include_directories(bench_comparison PRIVATE ${CMAKE_SOURCE_DIR}/benchmarks)

    add_executable(bench_dynamic benchmarks/bench_dynamic.cpp)
    target_link_libraries(bench_dynamic piccard_fhe)
    target_include_directories(bench_dynamic PRIVATE ${CMAKE_SOURCE_DIR}/benchmarks)

    add_executable(bench_threshold benchmarks/bench_threshold.cpp)
    target_link_libraries(bench_threshold piccard_fhe)
    target_include_directories(bench_threshold PRIVATE ${CMAKE_SOURCE_DIR}/benchmarks)
endif()

# =============================================================================
# Installation
# =============================================================================

install(TARGETS piccard_core
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)

if(OpenFHE_FOUND AND HAVE_PICCARD_FHE)
    install(TARGETS piccard_fhe
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
    )
endif()

install(DIRECTORY include/
    DESTINATION include
    FILES_MATCHING PATTERN "*.h"
)
