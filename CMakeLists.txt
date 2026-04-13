# CMakeLists.txt
# axioma-governance — L7 Proof-Carrying Governance Layer
#
# DVEC: v1.3
# DETERMINISM: D2 — Constrained Deterministic
# MEMORY: Bounded Allocation Model
#
# Copyright (c) 2026 The Murray Family Innovation Trust
# SPDX-License-Identifier: AGPL-3.0-or-later
# Patent: UK GB2521625.0

cmake_minimum_required(VERSION 3.14)

project(axioma-governance
    VERSION 0.1.0
    DESCRIPTION "L7 Proof-Carrying Governance Layer for Axioma Framework"
    LANGUAGES C
)

# =============================================================================
# DVEC Compiler Flags (Determinism Guarantees)
# DVEC-001 v1.3: bit-identical execution across compilers and optimisation levels
# =============================================================================

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

set(DVEC_FLAGS
    -Wall
    -Wextra
    -Wpedantic
    -Werror
    -fno-strict-aliasing
    -fwrapv
    -fno-tree-vectorize
    -fno-fast-math
    -fno-builtin
)

set(SAFETY_FLAGS
    -Wformat=2
    -Wformat-security
    -Wconversion
    -Wsign-conversion
    -Wcast-qual
    -Wcast-align
    -Wstrict-prototypes
    -Wmissing-prototypes
    -Wredundant-decls
    -Wnested-externs
    -Wshadow
    -Wundef
    -Wwrite-strings
    -Wswitch-default
    -Wswitch-enum
    -Wunreachable-code
    -Wfloat-equal
    -Wdouble-promotion
    -Wno-unused-function
)

foreach(flag ${DVEC_FLAGS} ${SAFETY_FLAGS})
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${flag}")
endforeach()

# =============================================================================
# libaxilog (sdk-root) — cryptographic substrate
# sha256.c removed — axilog_sha256/axilog_commit from libaxilog
# include/axilog/types.h removed — shadow copy deleted, resolves via sdk-root
# =============================================================================

set(AXILOG_SDK_ROOT "$ENV{HOME}/axilog/sdk-root"
    CACHE PATH "Path to axioma sdk-root installation")

# =============================================================================
# Library
# sha256.c removed — provided by libaxilog
# =============================================================================

set(AXIOMA_GOV_SOURCES
    src/jcs.c
    src/proof.c
    src/trace.c
    src/merkle.c
    src/verify.c
    src/anchor.c
    src/compliance.c
    src/fault.c
    # sha256.c removed — axilog_sha256() and axilog_commit() from libaxilog
)

set(LIB_HEADERS
    include/ax_governance.h
    include/ax_jcs.h
    include/ax_proof.h
    include/ax_trace.h
    include/ax_merkle.h
    include/ax_verify.h
    include/ax_anchor.h
    include/ax_compliance.h
    include/ax_fault.h
    # include/axilog/types.h removed — shadow copy deleted, resolves via sdk-root
)

add_library(axioma-governance STATIC ${AXIOMA_GOV_SOURCES})

target_include_directories(axioma-governance
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${AXILOG_SDK_ROOT}/include>
        $<INSTALL_INTERFACE:include>
)

target_link_libraries(axioma-governance PRIVATE
    ${AXILOG_SDK_ROOT}/lib/libaxilog.a
)

# Install library
install(TARGETS axioma-governance
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
)

# Install headers
install(FILES ${LIB_HEADERS}
    DESTINATION include/axioma-governance
)

# =============================================================================
# Tests
# test_sha256 removed — SHA-256 is now sourced from libaxilog (verified by
# axioma-l0's 257-test suite). Duplicate verification eliminated, not coverage.
# =============================================================================

option(BUILD_TESTS "Build unit tests" ON)

if(BUILD_TESTS)
    enable_testing()

    # Test: Proof Records
    add_executable(test_proof tests/test_proof.c)
    target_link_libraries(test_proof axioma-governance)
    add_test(NAME test_proof COMMAND test_proof)

    # Test: Mathematical Trace
    add_executable(test_trace tests/test_trace.c)
    target_link_libraries(test_trace axioma-governance)
    add_test(NAME test_trace COMMAND test_trace)

    # Test: Merkle Tree
    add_executable(test_merkle tests/test_merkle.c)
    target_link_libraries(test_merkle axioma-governance)
    add_test(NAME test_merkle COMMAND test_merkle)

    # Test: Cross-Layer Verification
    add_executable(test_verify tests/test_verify.c)
    target_link_libraries(test_verify axioma-governance)
    add_test(NAME test_verify COMMAND test_verify)

    # Test: Anchor Publication and Compliance Reports
    add_executable(test_anchor_compliance tests/test_anchor_compliance.c)
    target_link_libraries(test_anchor_compliance axioma-governance)
    add_test(NAME test_anchor_compliance COMMAND test_anchor_compliance)

    # Test: Fault Handling and Fallback Log
    add_executable(test_fault tests/test_fault.c)
    target_link_libraries(test_fault axioma-governance)
    add_test(NAME test_fault COMMAND test_fault)

    # Test: Golden Vectors (Determinism Certification)
    add_executable(test_golden tests/test_golden.c)
    target_link_libraries(test_golden axioma-governance)
    add_test(NAME test_golden COMMAND test_golden)

    # Test: Audit Finding Regressions (F009-F015)
    add_executable(test_audit_findings tests/test_audit_findings.c)
    target_link_libraries(test_audit_findings axioma-governance)
    add_test(NAME test_audit_findings COMMAND test_audit_findings)

endif()

# =============================================================================
# Documentation
# =============================================================================

option(BUILD_DOCS "Build documentation" OFF)

if(BUILD_DOCS)
    find_package(Doxygen)
    if(DOXYGEN_FOUND)
        set(DOXYGEN_IN ${CMAKE_CURRENT_SOURCE_DIR}/docs/Doxyfile.in)
        set(DOXYGEN_OUT ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile)
        configure_file(${DOXYGEN_IN} ${DOXYGEN_OUT} @ONLY)
        add_custom_target(docs
            COMMAND ${DOXYGEN_EXECUTABLE} ${DOXYGEN_OUT}
            WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
            COMMENT "Generating API documentation with Doxygen"
            VERBATIM
        )
    endif()
endif()

# =============================================================================
# Summary
# =============================================================================

message(STATUS "")
message(STATUS "axioma-governance ${PROJECT_VERSION}")
message(STATUS "================================================================================")
message(STATUS "  DVEC: v1.3")
message(STATUS "  Determinism: D2 — Constrained Deterministic")
message(STATUS "  SRS: SRS-007 v0.3 Audit-Frozen FINAL")
message(STATUS "  SDK Root:    ${AXILOG_SDK_ROOT}")
message(STATUS "")
message(STATUS "  C Standard: C99")
message(STATUS "  Build Tests: ${BUILD_TESTS}")
message(STATUS "  Build Docs: ${BUILD_DOCS}")
message(STATUS "================================================================================")
message(STATUS "")
