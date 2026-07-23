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

# Find OpenMP (for parallel loops and OpenFHE internal parallelism)
# On macOS with Homebrew libomp, help CMake locate the installation
if(APPLE AND NOT DEFINED OpenMP_CXX_FLAGS)
    execute_process(
        COMMAND brew --prefix libomp
        OUTPUT_VARIABLE HOMEBREW_LIBOMP_PREFIX
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
    )
    if(HOMEBREW_LIBOMP_PREFIX)
        set(OpenMP_CXX_FLAGS "-Xpreprocessor -fopenmp -I${HOMEBREW_LIBOMP_PREFIX}/include")
        set(OpenMP_CXX_LIB_NAMES "omp")
        set(OpenMP_omp_LIBRARY "${HOMEBREW_LIBOMP_PREFIX}/lib/libomp.dylib")
    endif()
endif()

find_package(OpenMP)
if(OpenMP_CXX_FOUND)
    message(STATUS "Found OpenMP: ${OpenMP_CXX_FLAGS}")
    # Ensure linker can find libomp (needed by both our code and OpenFHE)
    if(HOMEBREW_LIBOMP_PREFIX)
        link_directories(${HOMEBREW_LIBOMP_PREFIX}/lib)
    endif()
else()
    message(STATUS "OpenMP not found - parallel execution disabled")
endif()

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

# Find GMP (used by the AHE/DH-based comparison baselines: BCG12, SJ16).
# No standard FindGMP module ships with CMake, so locate it by hand.
find_path(GMP_INCLUDE_DIR gmp.h HINTS /opt/homebrew/include /usr/local/include)
find_library(GMP_LIBRARY NAMES gmp HINTS /opt/homebrew/lib /usr/local/lib)
if(GMP_INCLUDE_DIR AND GMP_LIBRARY)
    message(STATUS "Found GMP: ${GMP_LIBRARY}")
    set(GMP_FOUND TRUE)
    add_compile_definitions(HAVE_GMP)
else()
    message(STATUS "GMP not found - AHE-based baselines (BCG12, SJ16) disabled")
    set(GMP_FOUND FALSE)
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
endif()

# =============================================================================
# piccard_core: Pure math modules (no OpenFHE dependency)
# =============================================================================

set(PICCARD_CORE_SOURCES
    src/util/params.cpp
    src/core/minhash.cpp
    src/core/onehot_encoder.cpp
    src/core/sqrt_encoder.cpp
    src/core/bottom_structure.cpp
    src/core/threshold_poly.cpp
)

add_library(piccard_core ${PICCARD_CORE_SOURCES})
target_include_directories(piccard_core PUBLIC ${CMAKE_SOURCE_DIR}/include)
if(OpenMP_CXX_FOUND)
    target_link_libraries(piccard_core PUBLIC OpenMP::OpenMP_CXX)
endif()

# =============================================================================
# piccard_fhe: BFV context + engine (requires OpenFHE)
# =============================================================================

if(OpenFHE_FOUND)
    set(PICCARD_FHE_SOURCES
        src/fhe/bfv_context.cpp
        src/protocol/piccard.cpp
        src/protocol/dynamic_piccard.cpp
        src/protocol/threshold_piccard.cpp
        src/protocol/sqrt_piccard.cpp
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
# Comparison baselines (BCG12, SJ16)
# =============================================================================
# Each baseline lands as its own translation unit under src/baselines/ and
# implements include/baselines/pjs_baseline.h. The glob keeps this target
# valid while the directory is still empty.

file(GLOB PICCARD_BASELINE_SOURCES ${CMAKE_SOURCE_DIR}/src/baselines/*.cpp)

if(PICCARD_BASELINE_SOURCES AND GMP_FOUND AND HAVE_PICCARD_FHE)
    add_library(piccard_baselines ${PICCARD_BASELINE_SOURCES})
    target_link_libraries(piccard_baselines PUBLIC piccard_fhe ${GMP_LIBRARY})
    target_include_directories(piccard_baselines PUBLIC ${GMP_INCLUDE_DIR})
    if(OpenMP_CXX_FOUND)
        target_link_libraries(piccard_baselines PUBLIC OpenMP::OpenMP_CXX)
    endif()
    set(HAVE_PICCARD_BASELINES TRUE)
    message(STATUS "Comparison baselines enabled")
else()
    set(HAVE_PICCARD_BASELINES FALSE)
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

        add_executable(test_sqrt_encoder tests/unit/test_sqrt_encoder.cpp)
        target_link_libraries(test_sqrt_encoder piccard_core test_main)
        add_test(NAME SqrtEncoder COMMAND test_sqrt_encoder)

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

            add_executable(test_sqrt_piccard tests/unit/test_sqrt_piccard.cpp)
            target_link_libraries(test_sqrt_piccard piccard_fhe test_main)
            add_test(NAME SqrtPiccard COMMAND test_sqrt_piccard)

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

    add_executable(bench_sqrt_comparison benchmarks/bench_sqrt_comparison.cpp)
    target_link_libraries(bench_sqrt_comparison piccard_fhe)
    target_include_directories(bench_sqrt_comparison PRIVATE ${CMAKE_SOURCE_DIR}/benchmarks)

    add_executable(bench_onehot_sqrt benchmarks/bench_onehot_sqrt.cpp)
    target_link_libraries(bench_onehot_sqrt piccard_fhe)
    target_include_directories(bench_onehot_sqrt PRIVATE ${CMAKE_SOURCE_DIR}/benchmarks)

    add_executable(bench_crossover benchmarks/bench_crossover.cpp)
    target_link_libraries(bench_crossover piccard_fhe)
    target_include_directories(bench_crossover PRIVATE ${CMAKE_SOURCE_DIR}/benchmarks)
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
