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
    if(NOT BASE_OPENFHE_VERSION)
        message(FATAL_ERROR "OpenFHE package did not expose BASE_OPENFHE_VERSION")
    endif()
    set(PICCARD_CONFIGURED_OPENFHE_VERSION "${BASE_OPENFHE_VERSION}")
    execute_process(
        COMMAND git rev-parse HEAD
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        RESULT_VARIABLE PICCARD_BUILD_GIT_RESULT
        OUTPUT_VARIABLE PICCARD_CONFIGURED_BUILD_COMMIT
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
    )
    string(LENGTH "${PICCARD_CONFIGURED_BUILD_COMMIT}"
           PICCARD_CONFIGURED_BUILD_COMMIT_LENGTH)
    if(NOT PICCARD_BUILD_GIT_RESULT EQUAL 0 OR
       NOT PICCARD_CONFIGURED_BUILD_COMMIT_LENGTH EQUAL 40 OR
       PICCARD_CONFIGURED_BUILD_COMMIT MATCHES "[^0-9a-f]")
        message(FATAL_ERROR
                "Evidence builds require a full Git source commit")
    endif()
    execute_process(
        COMMAND git status --porcelain=v1 --untracked-files=all
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        RESULT_VARIABLE PICCARD_BUILD_DIRTY_RESULT
        OUTPUT_VARIABLE PICCARD_BUILD_DIRTY_OUTPUT
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
    )
    if(NOT PICCARD_BUILD_DIRTY_RESULT EQUAL 0)
        message(FATAL_ERROR "Cannot determine evidence build dirty state")
    endif()
    if(PICCARD_BUILD_DIRTY_OUTPUT STREQUAL "")
        set(PICCARD_CONFIGURED_BUILD_DIRTY 0)
    else()
        set(PICCARD_CONFIGURED_BUILD_DIRTY 1)
    endif()
    file(MAKE_DIRECTORY "${CMAKE_BINARY_DIR}/generated")
    configure_file(
        "${CMAKE_SOURCE_DIR}/cmake/build_info.h.in"
        "${CMAKE_BINARY_DIR}/generated/build_info.h"
        @ONLY
    )
    message(STATUS "Found OpenFHE: ${BASE_OPENFHE_VERSION}")
    message(STATUS "OpenFHE include: ${OpenFHE_INCLUDE}")
    message(STATUS "OpenFHE libraries: ${OpenFHE_LIBRARIES}")
    add_compile_definitions(
        HAVE_OPENFHE
        OPENFHE_VERSION=${BASE_OPENFHE_VERSION}
    )
else()
    message(STATUS "OpenFHE not found - FHE features disabled")
endif()

# Find GMP (used by the AHE/DH-based comparison baselines: BCG12, SJ16).
# No standard FindGMP module ships with CMake, so locate it by hand.
option(PICCARD_ENABLE_GMP "Enable GMP-based AHE baselines (BCG12/SJ16)" ON)

if(PICCARD_ENABLE_GMP)
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
else()
    message(STATUS "PICCARD_ENABLE_GMP=OFF - AHE-based baselines (BCG12, SJ16) disabled")
    set(GMP_FOUND FALSE)
endif()

# SHA-256 MinHash and the BCG12/SJ16 baselines require OpenSSL Crypto.
find_package(OpenSSL REQUIRED COMPONENTS Crypto)
message(STATUS "Found OpenSSL: ${OPENSSL_VERSION}")

# Include directories
include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_BINARY_DIR}/generated)
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

# Pure schema/parser support shared by bench_noise and its unit tests.
if(OpenFHE_FOUND)
    execute_process(
        COMMAND git rev-parse HEAD
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        OUTPUT_VARIABLE PICCARD_SOURCE_COMMIT
        OUTPUT_STRIP_TRAILING_WHITESPACE
        COMMAND_ERROR_IS_FATAL ANY
    )
    add_library(
        piccard_noise_calibration_schema
        benchmarks/noise_calibration_schema.cpp
    )
    target_include_directories(
        piccard_noise_calibration_schema
        PUBLIC
            ${CMAKE_SOURCE_DIR}/benchmarks
            ${CMAKE_SOURCE_DIR}/include
    )
    target_compile_definitions(
        piccard_noise_calibration_schema
        PRIVATE
            OPENFHE_VERSION=${BASE_OPENFHE_VERSION}
            PICCARD_OPENFHE_VERSION="${BASE_OPENFHE_VERSION}"
            PICCARD_SOURCE_COMMIT="${PICCARD_SOURCE_COMMIT}"
    )
    target_link_libraries(
        piccard_noise_calibration_schema
        PUBLIC
            OpenSSL::Crypto
            piccard_core
            piccard_security_profile
    )
endif()

# Shared deterministic serializers for all non-threshold benchmark schemas.
add_library(
    piccard_benchmark_serializers
    benchmarks/baseline_profile.cpp
    benchmarks/benchmark_profile.cpp
    benchmarks/benchmark_estimator_provenance.cpp
)
if(OpenFHE_FOUND)
    target_sources(
        piccard_benchmark_serializers
        PRIVATE benchmarks/benchmark_provenance.cpp
    )
endif()
target_include_directories(
    piccard_benchmark_serializers
    PUBLIC ${CMAKE_SOURCE_DIR}/benchmarks
)

# Typed Work-4-prefix CSV schema for real-dataset benchmark rows (Work 5
# Phase 5.2). Pure string/typed-token serialization, no OpenFHE dependency.
add_library(
    piccard_real_dataset_csv_schema
    benchmarks/real_dataset_csv_schema.cpp
)
target_include_directories(
    piccard_real_dataset_csv_schema
    PUBLIC ${CMAKE_SOURCE_DIR}/benchmarks ${CMAKE_SOURCE_DIR}/include
)
target_link_libraries(
    piccard_real_dataset_csv_schema
    PUBLIC piccard_benchmark_serializers piccard_data
)

# Canonical binary workload/trace support for reviewer comparisons.
add_library(
    piccard_comparison_workload
    benchmarks/comparison_workload.cpp
)
target_include_directories(
    piccard_comparison_workload
    PUBLIC ${CMAKE_SOURCE_DIR}/benchmarks
)
target_link_libraries(
    piccard_comparison_workload
    PUBLIC OpenSSL::Crypto
)

# =============================================================================
# piccard_core: Pure math modules (no OpenFHE dependency)
# =============================================================================

add_library(piccard_security_profile src/util/security_profile.cpp)
target_include_directories(
    piccard_security_profile
    PUBLIC ${CMAKE_SOURCE_DIR}/include
)

set(PICCARD_CORE_SOURCES
    src/util/params.cpp
    src/util/params_calibration.cpp
    src/core/minhash.cpp
    src/core/onehot_encoder.cpp
    src/core/sqrt_encoder.cpp
    src/core/bottom_structure.cpp
    src/core/threshold_poly.cpp
)

add_library(piccard_core ${PICCARD_CORE_SOURCES})
target_include_directories(piccard_core PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(
    piccard_core
    PUBLIC
        OpenSSL::Crypto
        piccard_security_profile
)
if(OpenMP_CXX_FOUND)
    target_link_libraries(piccard_core PUBLIC OpenMP::OpenMP_CXX)
endif()

# =============================================================================
# piccard_data: Strict real-dataset processed-output loader (Work 5 Phase 4).
# Pure parsing/validation, no OpenFHE dependency.
# =============================================================================

add_library(piccard_data src/data/real_dataset.cpp src/data/real_dataset_metrics.cpp)
target_include_directories(piccard_data PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(piccard_data PUBLIC OpenSSL::Crypto)

option(BUILD_TESTS "Build unit and integration tests" ON)
if(BUILD_TESTS)
    # Work 3 Phase 4: compile the frozen params.cpp in both current and
    # staged-v2 table modes. The v2 object intentionally does not link
    # piccard_core because that library contains the current-mode params.cpp.
    add_executable(
        noise_calibration_cutover_probe_current
        tests/fixtures/noise_calibration_cutover_probe.cpp
    )
    target_link_libraries(
        noise_calibration_cutover_probe_current
        PRIVATE piccard_core
    )

    add_library(
        piccard_params_calibration_v2_fixture
        OBJECT src/util/params.cpp
    )
    target_compile_definitions(
        piccard_params_calibration_v2_fixture
        PRIVATE
            PICCARD_NOISE_CALIBRATION_FILE=\"scripts/templates/noise_calibration_wrapper.inc\"
            PICCARD_PRE_THRESHOLD_CALIBRATION_ROWS_FILE=\"tests/fixtures/noise_calibration_pre_threshold_rows.inc\"
    )
    target_include_directories(
        piccard_params_calibration_v2_fixture
        PRIVATE
            ${CMAKE_SOURCE_DIR}
            ${CMAKE_SOURCE_DIR}/include
    )

    add_executable(
        noise_calibration_cutover_probe_v2
        tests/fixtures/noise_calibration_cutover_probe.cpp
        src/util/params_calibration.cpp
        $<TARGET_OBJECTS:piccard_params_calibration_v2_fixture>
    )
    target_compile_definitions(
        noise_calibration_cutover_probe_v2
        PRIVATE PICCARD_PRE_THRESHOLD_CALIBRATION_V2=1
    )
    target_link_libraries(
        noise_calibration_cutover_probe_v2
        PRIVATE
            OpenSSL::Crypto
            piccard_security_profile
    )
endif()

add_library(
    piccard_estimator_diagnostic
    benchmarks/estimator_diagnostic.cpp
)
target_link_libraries(piccard_estimator_diagnostic PUBLIC piccard_core)
target_include_directories(
    piccard_estimator_diagnostic
    PUBLIC ${CMAKE_SOURCE_DIR}/benchmarks
)

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
    target_link_libraries(piccard_benchmark_serializers PUBLIC piccard_fhe)
else()
    set(HAVE_PICCARD_FHE FALSE)
endif()

# =============================================================================
# Comparison baselines (BCG12, SJ16)
# =============================================================================
# Each baseline lands as its own translation unit under src/baselines/ and
# implements include/baselines/pjs_baseline.h. The glob keeps this target
# valid while the directory is still empty.

# piccard_paillier: GMP-only static lib for the Paillier AHE primitive. Built
# from an explicit source (not the glob below) so it compiles exactly once
# and never links OpenFHE/piccard_fhe - Paillier has no FHE dependency.
if(GMP_FOUND)
    add_library(piccard_paillier STATIC src/baselines/paillier.cpp)
    target_link_libraries(piccard_paillier PUBLIC ${GMP_LIBRARY})
    if(OpenMP_CXX_FOUND)
        target_link_libraries(piccard_paillier PUBLIC OpenMP::OpenMP_CXX)
    endif()
    target_include_directories(piccard_paillier PUBLIC ${GMP_INCLUDE_DIR} ${CMAKE_SOURCE_DIR}/include)
endif()

file(GLOB PICCARD_BASELINE_SOURCES CONFIGURE_DEPENDS ${CMAKE_SOURCE_DIR}/src/baselines/*.cpp)  # BCG12: track new files
# paillier.cpp is compiled once, in piccard_paillier above; keep it out of the
# OpenFHE-linked piccard_baselines glob below.
list(REMOVE_ITEM PICCARD_BASELINE_SOURCES "${CMAKE_SOURCE_DIR}/src/baselines/paillier.cpp")

if(PICCARD_BASELINE_SOURCES AND GMP_FOUND AND OpenSSL_FOUND AND HAVE_PICCARD_FHE)  # BCG12: require OpenSSL
    add_library(piccard_baselines ${PICCARD_BASELINE_SOURCES})
    target_link_libraries(piccard_baselines PUBLIC piccard_fhe ${GMP_LIBRARY} OpenSSL::Crypto)  # BCG12: link OpenSSL
    if(TARGET piccard_paillier)
        target_link_libraries(piccard_baselines PUBLIC piccard_paillier)
    endif()
    target_include_directories(piccard_baselines PUBLIC ${GMP_INCLUDE_DIR})
    if(OpenMP_CXX_FOUND)
        target_link_libraries(piccard_baselines PUBLIC OpenMP::OpenMP_CXX)
    endif()
    set(HAVE_PICCARD_BASELINES TRUE)
    add_compile_definitions(HAVE_PICCARD_BASELINES)     # BCG12: guards bench code
    message(STATUS "Comparison baselines enabled")
else()
    set(HAVE_PICCARD_BASELINES FALSE)
    message(STATUS "Comparison baselines disabled (need GMP + OpenSSL + OpenFHE)")  # BCG12
endif()

# =============================================================================
# Tests
# =============================================================================

if(BUILD_TESTS)
    enable_testing()
    add_test(
        NAME NoiseCalibrationCutoverProbeCurrent
        COMMAND noise_calibration_cutover_probe_current
    )
    add_test(
        NAME NoiseCalibrationCutoverProbeV2
        COMMAND noise_calibration_cutover_probe_v2
    )
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

        add_executable(
            test_security_profile
            tests/unit/test_security_profile.cpp
        )
        target_link_libraries(
            test_security_profile
            piccard_security_profile
            test_main
        )
        add_test(NAME SecurityProfile COMMAND test_security_profile)

        add_executable(test_minhash tests/unit/test_minhash.cpp)
        target_link_libraries(test_minhash piccard_core test_main)
        add_test(NAME MinHash COMMAND test_minhash)

        add_executable(test_real_dataset tests/unit/test_real_dataset.cpp)
        target_link_libraries(
            test_real_dataset
            piccard_data
            OpenSSL::Crypto
            test_main
        )
        target_compile_definitions(
            test_real_dataset
            PRIVATE PICCARD_SOURCE_DIR="${CMAKE_SOURCE_DIR}"
        )
        add_test(NAME RealDataset COMMAND test_real_dataset)

        add_executable(test_real_dataset_metrics tests/unit/test_real_dataset_metrics.cpp)
        target_link_libraries(
            test_real_dataset_metrics
            piccard_data
            piccard_real_dataset_csv_schema
            test_main
        )
        target_include_directories(
            test_real_dataset_metrics
            PRIVATE ${CMAKE_SOURCE_DIR}/benchmarks
        )
        add_test(NAME RealDatasetMetrics COMMAND test_real_dataset_metrics)

        add_executable(
            test_comparison_workload
            tests/unit/test_comparison_workload.cpp
        )
        target_link_libraries(
            test_comparison_workload
            piccard_comparison_workload
            test_main
        )
        target_include_directories(
            test_comparison_workload
            PRIVATE ${CMAKE_SOURCE_DIR}/benchmarks
        )
        target_compile_definitions(
            test_comparison_workload
            PRIVATE PICCARD_SOURCE_DIR="${CMAKE_SOURCE_DIR}"
        )
        add_test(NAME ComparisonWorkload COMMAND test_comparison_workload)

        add_executable(
            test_estimator_diagnostic
            tests/unit/test_estimator_diagnostic.cpp
        )
        target_link_libraries(
            test_estimator_diagnostic
            piccard_estimator_diagnostic
            test_main
        )
        target_include_directories(
            test_estimator_diagnostic
            PRIVATE ${CMAKE_SOURCE_DIR}/benchmarks
        )
        add_test(NAME EstimatorDiagnostic COMMAND test_estimator_diagnostic)

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

        # Paillier AHE primitive test (GMP-only, no OpenFHE dependency)
        if(TARGET piccard_paillier)
            add_executable(test_paillier tests/unit/test_paillier.cpp)
            target_link_libraries(test_paillier piccard_paillier test_main)
            add_test(NAME Paillier COMMAND test_paillier)
        endif()

        # SJ16 protocol engine test (needs piccard_baselines for sj16.cpp).
        if(TARGET piccard_baselines)
            add_executable(test_sj16 tests/unit/test_sj16.cpp)
            target_link_libraries(test_sj16 piccard_baselines test_main)
            # libgmpxx supplies mpz_class operator<< used by GTest's printer.
            find_library(GMPXX_LIBRARY NAMES gmpxx HINTS /opt/homebrew/lib /usr/local/lib)
            if(GMPXX_LIBRARY)
                target_link_libraries(test_sj16 ${GMPXX_LIBRARY})
            endif()
            add_test(NAME SJ16 COMMAND test_sj16)
        endif()

        # FHE tests (require OpenFHE)
        if(OpenFHE_FOUND AND HAVE_PICCARD_FHE)
            add_executable(test_bfv_context tests/unit/test_bfv_context.cpp)
            target_link_libraries(test_bfv_context piccard_fhe test_main)
            add_test(NAME BFVContext COMMAND test_bfv_context)

            add_executable(test_piccard_engine tests/unit/test_piccard_engine.cpp)
            target_link_libraries(test_piccard_engine piccard_fhe test_main)
            add_test(NAME PiccardEngine COMMAND test_piccard_engine)

            add_executable(
                test_piccard_engine_legacy_compile
                tests/unit/test_piccard_engine_legacy_compile.cpp
                src/protocol/piccard_engine.cpp
            )
            target_link_libraries(
                test_piccard_engine_legacy_compile
                piccard_fhe
                test_main
            )
            add_test(
                NAME PiccardEngineLegacyCompile
                COMMAND test_piccard_engine_legacy_compile
            )

            add_executable(test_dynamic_engine tests/unit/test_dynamic_engine.cpp)
            target_link_libraries(test_dynamic_engine piccard_fhe test_main)
            add_test(NAME DynamicEngine COMMAND test_dynamic_engine)

            add_executable(test_threshold_engine tests/unit/test_threshold_engine.cpp)
            target_link_libraries(test_threshold_engine piccard_fhe test_main)
            add_test(NAME ThresholdEngine COMMAND test_threshold_engine)

            add_executable(test_sqrt_piccard tests/unit/test_sqrt_piccard.cpp)
            target_link_libraries(test_sqrt_piccard piccard_fhe test_main)
            add_test(NAME SqrtPiccard COMMAND test_sqrt_piccard)

            # Work 2 Phase 3: compile the production params adapter against a
            # toy requested-8192 / realized-16384 calibration fixture. This
            # target intentionally does not link piccard_core or piccard_fhe,
            # because both contain the normal params.cpp object.
            add_library(
                piccard_params_grown_fixture
                OBJECT src/util/params.cpp
            )
            target_compile_definitions(
                piccard_params_grown_fixture
                PRIVATE
                    PICCARD_NOISE_CALIBRATION_FILE=\"tests/fixtures/noise_calibration_grown_rows.inc\"
            )
            target_include_directories(
                piccard_params_grown_fixture
                PRIVATE
                    ${CMAKE_SOURCE_DIR}
                    ${CMAKE_SOURCE_DIR}/include
            )

            add_executable(
                test_piccard_grown_ring
                tests/unit/test_piccard_engine.cpp
                tests/unit/test_sqrt_piccard.cpp
                src/util/params_calibration.cpp
                src/core/minhash.cpp
                src/core/onehot_encoder.cpp
                src/core/sqrt_encoder.cpp
                src/core/bottom_structure.cpp
                src/fhe/bfv_context.cpp
                src/protocol/piccard.cpp
                src/protocol/dynamic_piccard.cpp
                src/protocol/sqrt_piccard.cpp
                $<TARGET_OBJECTS:piccard_params_grown_fixture>
            )
            target_compile_definitions(
                test_piccard_grown_ring
                PRIVATE PICCARD_GROWN_RING_FIXTURE
            )
            target_link_libraries(
                test_piccard_grown_ring
                PRIVATE
                    test_main
                    piccard_security_profile
                    OpenSSL::Crypto
                    ${OpenFHE_LIBRARIES}
            )
            if(OpenMP_CXX_FOUND)
                target_link_libraries(
                    piccard_params_grown_fixture
                    PRIVATE OpenMP::OpenMP_CXX
                )
                target_link_libraries(
                    test_piccard_grown_ring
                    PRIVATE OpenMP::OpenMP_CXX
                )
            endif()
            add_test(NAME PiccardGrownRing COMMAND test_piccard_grown_ring)

            # Benchmark utility tests (DispersionStats / ComputeDispersion)
            add_executable(test_benchmark_utils tests/unit/test_benchmark_utils.cpp)
            target_link_libraries(
                test_benchmark_utils
                piccard_fhe
                piccard_benchmark_serializers
                test_main
            )
            target_include_directories(test_benchmark_utils PRIVATE ${CMAKE_SOURCE_DIR}/benchmarks)
            add_test(NAME BenchmarkUtils COMMAND test_benchmark_utils)

            add_executable(
                test_estimator_provenance_serializers
                tests/unit/test_estimator_provenance_serializers.cpp
            )
            target_link_libraries(
                test_estimator_provenance_serializers
                piccard_fhe
                piccard_benchmark_serializers
                test_main
            )
            target_include_directories(
                test_estimator_provenance_serializers
                PRIVATE ${CMAKE_SOURCE_DIR}/benchmarks
            )
            target_compile_definitions(
                test_estimator_provenance_serializers
                PRIVATE
                    PICCARD_RUNNER_FIXTURE_DIR="${CMAKE_SOURCE_DIR}/tests/fixtures/runner"
            )
            add_test(
                NAME EstimatorProvenanceSerializers
                COMMAND test_estimator_provenance_serializers
            )

            add_executable(
                test_benchmark_profile
                tests/unit/test_benchmark_profile.cpp
            )
            target_link_libraries(
                test_benchmark_profile
                piccard_fhe
                piccard_benchmark_serializers
                test_main
            )
            target_include_directories(
                test_benchmark_profile
                PRIVATE ${CMAKE_SOURCE_DIR}/benchmarks
            )
            add_test(NAME BenchmarkProfile COMMAND test_benchmark_profile)

            add_executable(
                test_baseline_profile
                tests/unit/test_baseline_profile.cpp
            )
            target_link_libraries(
                test_baseline_profile
                piccard_benchmark_serializers
                test_main
            )
            target_include_directories(
                test_baseline_profile
                PRIVATE ${CMAKE_SOURCE_DIR}/benchmarks
            )
            add_test(NAME BaselineProfile COMMAND test_baseline_profile)

            add_executable(
                test_noise_calibration_schema
                tests/unit/test_noise_calibration_schema.cpp
            )
            target_link_libraries(
                test_noise_calibration_schema
                piccard_noise_calibration_schema
                test_main
            )
            target_include_directories(
                test_noise_calibration_schema
                PRIVATE ${CMAKE_SOURCE_DIR}/benchmarks
            )
            target_compile_definitions(
                test_noise_calibration_schema
                PRIVATE PICCARD_SOURCE_DIR="${CMAKE_SOURCE_DIR}"
            )
            add_test(
                NAME NoiseCalibrationSchema
                COMMAND test_noise_calibration_schema
            )

            add_executable(
                test_threshold_profile_compat
                tests/unit/test_threshold_profile_compat.cpp
            )
            target_link_libraries(
                test_threshold_profile_compat
                piccard_fhe
                test_main
            )
            target_include_directories(
                test_threshold_profile_compat
                PRIVATE ${CMAKE_SOURCE_DIR}/benchmarks
            )
            add_test(
                NAME ThresholdProfileCompat
                COMMAND test_threshold_profile_compat
            )

            # Integration test
            add_executable(test_piccard_e2e tests/integration/test_piccard_e2e.cpp)
            target_link_libraries(test_piccard_e2e piccard_fhe test_main)
            add_test(NAME PiccardE2E COMMAND test_piccard_e2e)

            if(HAVE_PICCARD_BASELINES)                              # BCG12 unit tests
                add_executable(test_group tests/unit/test_group.cpp)
                target_link_libraries(test_group piccard_baselines test_main)
                add_test(NAME Group COMMAND test_group)

                add_executable(test_dgt12_psica tests/unit/test_dgt12_psica.cpp)  # BCG12
                target_link_libraries(test_dgt12_psica piccard_baselines test_main)  # BCG12
                add_test(NAME Dgt12PsiCa COMMAND test_dgt12_psica)  # BCG12

                add_executable(test_bcg12 tests/unit/test_bcg12.cpp)  # BCG12
                target_link_libraries(test_bcg12 piccard_baselines test_main)  # BCG12
                add_test(NAME Bcg12 COMMAND test_bcg12)  # BCG12
            endif()
        endif()
    else()
        message(STATUS "GTest not found, skipping tests")
    endif()

    # Cross-work approval-record verifier: pure Python standard library, so it
    # is registered independently of GTest. The suite imports itself as
    # tests.scripts.test_verify_work_approval, hence the source-tree WORKING_DIRECTORY.
    #
    # Python3 is REQUIRED here rather than optional: this suite *is* the approval
    # gate, so a build tree that quietly dropped it would still report
    # "100% tests passed" -- the one outcome a gate must never produce. With
    # BUILD_TESTS=ON, a missing interpreter is a configuration error.
    find_package(Python3 COMPONENTS Interpreter QUIET)
    if(NOT Python3_Interpreter_FOUND)
        message(FATAL_ERROR
                "BUILD_TESTS=ON requires a Python3 interpreter for the "
                "VerifyWorkApproval approval gate. Install Python 3 or configure "
                "with -DBUILD_TESTS=OFF; the gate must not be silently skipped.")
    endif()
    add_test(NAME VerifyWorkApproval
             COMMAND ${Python3_EXECUTABLE} -m unittest -v
                     tests.scripts.test_verify_work_approval
             WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
    add_test(NAME SanitizerRunnerForwarding
             COMMAND ${Python3_EXECUTABLE} -m unittest -v
                     tests.scripts.test_sanitizer_runner_forwarding
             WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
    add_test(NAME NoiseProfileRunner
             COMMAND ${Python3_EXECUTABLE} -m unittest -v
                     tests.scripts.test_run_noise_profiles
             WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
    add_test(NAME CalibrationTableGenerator
             COMMAND ${Python3_EXECUTABLE} -m unittest -v
                     tests.scripts.test_make_calibration_table
             WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
    add_test(NAME CalibrationCutover
             COMMAND ${Python3_EXECUTABLE} -m unittest -v
                     tests.scripts.test_apply_calibration_cutover
             WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
    add_test(NAME CalibrationArchive
             COMMAND ${Python3_EXECUTABLE} -m unittest -v
                     tests.scripts.test_make_calibration_archive
             WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
    add_test(NAME ReportingTaxonomy
             COMMAND ${Python3_EXECUTABLE} -m unittest -v
                     tests.scripts.test_reporting_taxonomy
             WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
    add_test(NAME PreThresholdProfileRunner
             COMMAND ${Python3_EXECUTABLE} -m unittest -v
                     tests.scripts.test_run_pre_threshold_profiles
             WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
    add_test(NAME VerifyReviewComparison
             COMMAND ${Python3_EXECUTABLE} -m unittest -v
                     tests.scripts.test_verify_review_comparison
             WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
    add_test(NAME VerifyBenchmarkProvenance
             COMMAND ${Python3_EXECUTABLE} -m unittest -v
                     tests.scripts.test_verify_benchmark_provenance
             WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
    add_test(NAME VerifySJ16Extrapolation
             COMMAND ${Python3_EXECUTABLE} -m unittest -v
                     tests.scripts.test_verify_sj16_extrapolation
             WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
    add_test(NAME RealDatasetPreprocess
             COMMAND ${Python3_EXECUTABLE} -m unittest -v
                     tests.scripts.test_real_dataset_preprocess
             WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
endif()

# =============================================================================
# Benchmarks
# =============================================================================

option(BUILD_BENCHMARKS "Build benchmark executables" ON)

if(BUILD_BENCHMARKS)
    add_executable(
        bench_estimator_bias
        benchmarks/bench_estimator_bias.cpp
    )
    target_link_libraries(
        bench_estimator_bias
        piccard_estimator_diagnostic
    )
    target_include_directories(
        bench_estimator_bias
        PRIVATE ${CMAKE_SOURCE_DIR}/benchmarks
    )
endif()

if(BUILD_BENCHMARKS AND OpenFHE_FOUND AND HAVE_PICCARD_FHE)
    add_executable(bench_piccard benchmarks/bench_piccard.cpp)
    target_link_libraries(
        bench_piccard
        piccard_fhe
        piccard_benchmark_serializers
    )
    target_include_directories(bench_piccard PRIVATE ${CMAKE_SOURCE_DIR}/benchmarks)

    add_executable(bench_comparison benchmarks/bench_comparison.cpp)
    target_link_libraries(
        bench_comparison
        piccard_fhe
        piccard_benchmark_serializers
    )
    if(HAVE_PICCARD_BASELINES)                              # BCG12: enable baseline rows
        target_link_libraries(bench_comparison piccard_baselines)
    endif()
    target_include_directories(bench_comparison PRIVATE ${CMAKE_SOURCE_DIR}/benchmarks)
    if(BUILD_TESTS)
        add_test(
            NAME BenchmarkProfileExecutables
            COMMAND ${Python3_EXECUTABLE}
                    ${CMAKE_SOURCE_DIR}/tests/scripts/test_benchmark_profile_executables.py
                    $<TARGET_FILE:bench_comparison>
        )
    endif()
    # SJ16 baseline (Phase 4): link the AHE engine and define HAVE_SJ16 only when
    # the GMP-backed baselines exist (implies GMP + Paillier + OpenFHE).
    if(HAVE_PICCARD_BASELINES)
        target_link_libraries(bench_comparison piccard_baselines)
        target_compile_definitions(bench_comparison PRIVATE HAVE_SJ16)
        find_library(GMPXX_LIBRARY NAMES gmpxx HINTS /opt/homebrew/lib /usr/local/lib)
        if(GMPXX_LIBRARY)
            target_link_libraries(bench_comparison ${GMPXX_LIBRARY})
        endif()
    endif()

    if(HAVE_PICCARD_BASELINES)
        add_executable(
            bench_review_comparison
            benchmarks/bench_review_comparison.cpp
        )
        target_link_libraries(
            bench_review_comparison
            PRIVATE
                piccard_fhe
                piccard_baselines
                piccard_benchmark_serializers
                piccard_comparison_workload
        )
        target_include_directories(
            bench_review_comparison
            PRIVATE ${CMAKE_SOURCE_DIR}/benchmarks
        )
        find_library(
            PICCARD_REVIEW_GMPXX_LIBRARY
            NAMES gmpxx
            HINTS /opt/homebrew/lib /usr/local/lib
        )
        if(PICCARD_REVIEW_GMPXX_LIBRARY)
            target_link_libraries(
                bench_review_comparison
                PRIVATE ${PICCARD_REVIEW_GMPXX_LIBRARY}
            )
        endif()
        if(BUILD_TESTS)
            add_test(
                NAME ReviewComparisonCli
                COMMAND ${Python3_EXECUTABLE}
                        ${CMAKE_SOURCE_DIR}/tests/scripts/test_review_comparison_cli.py
                        $<TARGET_FILE:bench_review_comparison>
            )
        endif()
    endif()

    add_executable(bench_dynamic benchmarks/bench_dynamic.cpp)
    target_link_libraries(
        bench_dynamic
        piccard_fhe
        piccard_benchmark_serializers
    )
    target_include_directories(bench_dynamic PRIVATE ${CMAKE_SOURCE_DIR}/benchmarks)
    if(BUILD_TESTS)
        add_test(NAME BenchDynamicProbeIsolation
                 COMMAND ${Python3_EXECUTABLE}
                         ${CMAKE_SOURCE_DIR}/tests/scripts/test_bench_dynamic_probe_isolation.py
                         $<TARGET_FILE:bench_dynamic>)
    endif()

    add_executable(bench_threshold benchmarks/bench_threshold.cpp)
    target_link_libraries(
        bench_threshold
        piccard_fhe
        piccard_benchmark_serializers
    )
    target_include_directories(bench_threshold PRIVATE ${CMAKE_SOURCE_DIR}/benchmarks)

    add_executable(bench_sqrt_comparison benchmarks/bench_sqrt_comparison.cpp)
    target_link_libraries(
        bench_sqrt_comparison
        piccard_fhe
        piccard_benchmark_serializers
    )
    target_include_directories(bench_sqrt_comparison PRIVATE ${CMAKE_SOURCE_DIR}/benchmarks)

    add_executable(bench_onehot_sqrt benchmarks/bench_onehot_sqrt.cpp)
    target_link_libraries(
        bench_onehot_sqrt
        piccard_fhe
        piccard_benchmark_serializers
    )
    target_include_directories(bench_onehot_sqrt PRIVATE ${CMAKE_SOURCE_DIR}/benchmarks)

    add_executable(bench_crossover benchmarks/bench_crossover.cpp)
    target_link_libraries(
        bench_crossover
        piccard_fhe
        piccard_benchmark_serializers
    )
    target_include_directories(bench_crossover PRIVATE ${CMAKE_SOURCE_DIR}/benchmarks)

    # Decryption-noise calibration for noise flooding (R2-W6). Not a timing
    # benchmark: it measures the evaluation-noise bound that sizes the
    # flooding term, and emits the calibration table the parameter selection
    # in params.cpp is built from.
    add_executable(bench_noise benchmarks/bench_noise.cpp)
    target_link_libraries(
        bench_noise
        piccard_fhe
        piccard_noise_calibration_schema
    )
    target_include_directories(bench_noise PRIVATE ${CMAKE_SOURCE_DIR}/benchmarks)
    if(BUILD_TESTS)
        add_test(
            NAME NoiseStrictMeasurementCleanup
            COMMAND bench_noise --strict_cleanup_probe
        )
        set_tests_properties(
            NoiseStrictMeasurementCleanup
            PROPERTIES
                FAIL_REGULAR_EXPRESSION "strict cleanup probe failed"
                PASS_REGULAR_EXPRESSION
                    "strict cleanup probe passed: iterations=3"
                TIMEOUT 60
        )
        add_test(
            NAME NoiseCandidatePlaintextCompatibility
            COMMAND bench_noise --candidate_plaintext_probe
        )
        set_tests_properties(
            NoiseCandidatePlaintextCompatibility
            PROPERTIES
                FAIL_REGULAR_EXPRESSION
                    "candidate plaintext probe failed"
                PASS_REGULAR_EXPRESSION
                    "candidate plaintext probe passed: natural_N=2048 natural_p=12289 calibrated_N=4096 candidate_p=40961 consumers=2 helper_boundary=577->641 low_max_reject=OK packed_encrypt=OK"
                TIMEOUT 60
        )
        add_test(NAME NoiseDetailIdentityMapping
                 COMMAND bench_noise --detail_identity_probe)
        set_tests_properties(
            NoiseDetailIdentityMapping
            PROPERTIES
                FAIL_REGULAR_EXPRESSION "detail identity probe failed"
                PASS_REGULAR_EXPRESSION "detail identity probe passed: failed_depth=2 success_depth=2"
                TIMEOUT 5)
        add_test(
            NAME NoisePreThresholdCoverage
            COMMAND bench_noise --coverage --pre_threshold
        )
        add_test(
            NAME NoisePreThresholdRejectsThreshold
            COMMAND
                bench_noise
                --pre_threshold
                --profile_manifest=profiles.json
                --profile=primary40
                --key_id=primary40:threshold:STD128
                --circuit=threshold
                --security=STD128
                --scaling_mod_grid=40
                --max_depth_delta=0
                --ring_candidates=8192
                --timeout_seconds=1
                --transcript_stat_bits=40
                --max_queries=1
                --margin=8
                --reps=5
                --seed=20260729
        )
        add_test(
            NAME NoisePreThresholdSmoke
            COMMAND
                bench_noise
                --pre_threshold
                --smoke
                --profile_manifest=profiles.json
                --profile=primary40
                --key_id=primary40:onehot:STD128
                --circuit=onehot
                --security=STD128
                --scaling_mod_grid=40
                --max_depth_delta=0
                --ring_candidates=8192
                --timeout_seconds=30
                --transcript_stat_bits=40
                --max_queries=1048576
                --margin=8
                --reps=1
                --seed=20260729
        )
        add_test(
            NAME NoisePreThresholdRejectsNonNaturalFirstRing
            COMMAND
                bench_noise
                --pre_threshold
                --smoke
                --profile_manifest=profiles.json
                --profile=primary40
                --key_id=primary40:onehot:STD128
                --circuit=onehot
                --security=STD128
                --scaling_mod_grid=40
                --max_depth_delta=0
                --ring_candidates=16384
                --timeout_seconds=30
                --transcript_stat_bits=40
                --max_queries=1048576
                --margin=8
                --reps=1
                --seed=20260729
        )
        add_test(
            NAME NoisePreThresholdGrownSmoke
            COMMAND
                bench_noise
                --pre_threshold
                --smoke
                --profile_manifest=profiles.json
                --profile=primary40
                --key_id=primary40:onehot:STD128
                --circuit=onehot
                --security=STD128
                --scaling_mod_grid=40
                --max_depth_delta=0
                --ring_candidates=8192,16384
                --timeout_seconds=30
                --transcript_stat_bits=40
                --max_queries=1048576
                --margin=8
                --reps=1
                --seed=20260729
        )
        add_test(
            NAME NoisePreThresholdRejectsProfilePolicyMismatch
            COMMAND
                bench_noise
                --pre_threshold
                --smoke
                --profile_manifest=profiles.json
                --profile=primary40
                --key_id=primary40:onehot:STD128
                --circuit=onehot
                --security=STD128
                --scaling_mod_grid=40
                --max_depth_delta=0
                --ring_candidates=8192
                --timeout_seconds=30
                --transcript_stat_bits=64
                --max_queries=1048576
                --margin=8
                --reps=1
                --seed=20260729
        )
        set_tests_properties(
            NoisePreThresholdRejectsThreshold
            PROPERTIES
                WILL_FAIL TRUE
                TIMEOUT 5
        )
        set_tests_properties(
            NoisePreThresholdSmoke
            PROPERTIES
                FAIL_REGULAR_EXPRESSION "FAILED:"
                PASS_REGULAR_EXPRESSION "dec-OK"
                TIMEOUT 30
        )
        set_tests_properties(
            NoisePreThresholdRejectsNonNaturalFirstRing
            PROPERTIES
                WILL_FAIL TRUE
                TIMEOUT 30
        )
        set_tests_properties(
            NoisePreThresholdGrownSmoke
            PROPERTIES
                FAIL_REGULAR_EXPRESSION "FAILED:"
                PASS_REGULAR_EXPRESSION
                    "requested N=8192.*natural N=8192.*calibrated N=16384.*realized N=16384"
                TIMEOUT 30
        )
        set_tests_properties(
            NoisePreThresholdRejectsProfilePolicyMismatch
            PROPERTIES
                WILL_FAIL TRUE
                TIMEOUT 5
        )
    endif()

    # SJ16 calibration tool (Phase 3): own CLI, not a ctest. Needs the SJ16
    # engine (piccard_baselines pulls SJ16 + Paillier + GMP + OpenFHE) and OpenMP.
    if(HAVE_PICCARD_BASELINES)
        add_executable(bench_sj16_calibrate benchmarks/bench_sj16_calibrate.cpp)
        target_link_libraries(bench_sj16_calibrate piccard_baselines)
        if(OpenMP_CXX_FOUND)
            target_link_libraries(bench_sj16_calibrate OpenMP::OpenMP_CXX)
        endif()
        find_library(GMPXX_LIBRARY NAMES gmpxx HINTS /opt/homebrew/lib /usr/local/lib)
        if(GMPXX_LIBRARY)
            target_link_libraries(bench_sj16_calibrate ${GMPXX_LIBRARY})
        endif()
        target_include_directories(bench_sj16_calibrate PRIVATE ${CMAKE_SOURCE_DIR}/benchmarks)
    endif()
endif()

# =============================================================================
# Installation
# =============================================================================

install(TARGETS piccard_core piccard_security_profile
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
