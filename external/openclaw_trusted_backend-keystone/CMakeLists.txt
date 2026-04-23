cmake_minimum_required(VERSION 3.10)
project(openclaw_keystone_trusted_backend C CXX ASM)

function(resolve_keystone_library out_var primary_path fallback_path)
  if (EXISTS "${primary_path}")
    set(${out_var} "${primary_path}" PARENT_SCOPE)
    return()
  endif()
  if (EXISTS "${fallback_path}")
    set(${out_var} "${fallback_path}" PARENT_SCOPE)
    return()
  endif()
  message(FATAL_ERROR
    "Unable to locate ${out_var}. Checked:\n"
    "  ${primary_path}\n"
    "  ${fallback_path}")
endfunction()

if (NOT DEFINED KEYSTONE_SDK_DIR)
  message(FATAL_ERROR "Please set KEYSTONE_SDK_DIR to an installed Keystone SDK path")
endif()

if (NOT DEFINED KEYSTONE_BITS)
  set(KEYSTONE_BITS 64)
endif()

set(ENV{KEYSTONE_SDK_DIR} ${KEYSTONE_SDK_DIR})

if (DEFINED PATH)
  set(ENV{PATH} ${PATH})
endif()

set(KEYSTONE_MACROS_CMAKE "${KEYSTONE_SDK_DIR}/cmake/macros.cmake")
if (NOT EXISTS "${KEYSTONE_MACROS_CMAKE}")
  set(KEYSTONE_MACROS_CMAKE "${KEYSTONE_SDK_DIR}/macros.cmake")
endif()
include(${KEYSTONE_MACROS_CMAKE})
include(ExternalProject)

use_riscv_toolchain(${KEYSTONE_BITS})

include_directories(AFTER ${KEYSTONE_SDK_DIR}/include)
get_filename_component(KEYSTONE_TOOLCHAIN_BIN_DIR "${CMAKE_C_COMPILER}" DIRECTORY)
get_filename_component(KEYSTONE_TOOLCHAIN_ROOT "${KEYSTONE_TOOLCHAIN_BIN_DIR}/.." ABSOLUTE)

# Keystone's add_eyrie_runtime helper forwards CMAKE_C_FLAGS through an
# ExternalProject argument that breaks when multiple flags are packed into one
# quoted string. Keep the runtime configure path on a single safe flag.
set(CMAKE_C_FLAGS "-Wall")

resolve_keystone_library(
  KEYSTONE_LIB_HOST
  "${KEYSTONE_SDK_DIR}/lib/libkeystone-host.a"
  "${KEYSTONE_SDK_DIR}/src/host/libkeystone-host.a")
resolve_keystone_library(
  KEYSTONE_LIB_EDGE
  "${KEYSTONE_SDK_DIR}/lib/libkeystone-edge.a"
  "${KEYSTONE_SDK_DIR}/src/edge/libkeystone-edge.a")
resolve_keystone_library(
  KEYSTONE_LIB_VERIFIER
  "${KEYSTONE_SDK_DIR}/lib/libkeystone-verifier.a"
  "${KEYSTONE_SDK_DIR}/src/verifier/libkeystone-verifier.a")
resolve_keystone_library(
  KEYSTONE_LIB_EAPP
  "${KEYSTONE_SDK_DIR}/lib/libkeystone-eapp.a"
  "${KEYSTONE_SDK_DIR}/src/app/libkeystone-eapp.a")

set(ca_target keystone_example_openclaw_trusted_backend)
set(server_target keystone_example_openclaw_trusted_backend_server)
set(eapp_target openclaw-keystone-backend-eapp)
set(package_runner_target openclaw-keystone-package-runner)
set(package_name openclaw-keystone-trusted-backend.ke)
set(package_script
    "./${package_runner_target} ${eapp_target} eyrie-rt loader.bin ${server_target} ${ca_target}")
set(eyrie_plugins "none")
set(eyrie_files_to_copy .options_log eyrie-rt loader.bin)

add_executable(${ca_target}
  host/main.c
  host/keystone_enclave_bridge.cpp)
target_include_directories(${ca_target}
  PRIVATE include
  PRIVATE ${KEYSTONE_SDK_DIR}/include/common
  PRIVATE ${KEYSTONE_SDK_DIR}/include/host
  PRIVATE ${KEYSTONE_SDK_DIR}/include/edge
  PRIVATE ${KEYSTONE_SDK_DIR}/include/verifier
  PRIVATE host
  PRIVATE ${KEYSTONE_TOOLCHAIN_ROOT}/include)
target_link_directories(${ca_target} PRIVATE ${KEYSTONE_TOOLCHAIN_ROOT}/lib)
target_link_libraries(${ca_target}
  PRIVATE crypto
  PRIVATE ${KEYSTONE_LIB_HOST}
  PRIVATE ${KEYSTONE_LIB_EDGE}
  PRIVATE ${KEYSTONE_LIB_VERIFIER})
set_target_properties(${ca_target}
  PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED YES CXX_EXTENSIONS NO)

add_executable(${server_target} host/backend_server_c.c)
target_include_directories(${server_target}
  PRIVATE include
  PRIVATE ${KEYSTONE_TOOLCHAIN_ROOT}/include)
target_link_directories(${server_target} PRIVATE ${KEYSTONE_TOOLCHAIN_ROOT}/lib)
target_link_libraries(${server_target} PRIVATE crypto)

add_executable(${eapp_target} eapp/openclaw_keystone_backend_eapp.c)
target_link_options(${eapp_target} PRIVATE "-Wl,-e,main")
target_link_libraries(${eapp_target}
  "-nostdlib -static"
  ${KEYSTONE_LIB_EAPP}
  ${KEYSTONE_LIB_EDGE})
target_include_directories(${eapp_target}
  PRIVATE ${KEYSTONE_SDK_DIR}/include/app
  PRIVATE ${KEYSTONE_SDK_DIR}/include/edge)

add_executable(${package_runner_target}
  host/package_runner.cpp
  host/keystone_attestor.cpp)
target_link_libraries(${package_runner_target}
  ${KEYSTONE_LIB_HOST}
  ${KEYSTONE_LIB_EDGE}
  ${KEYSTONE_LIB_VERIFIER})
set_target_properties(${package_runner_target}
  PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED YES CXX_EXTENSIONS NO)
target_include_directories(${package_runner_target}
  PRIVATE ${KEYSTONE_SDK_DIR}/include/common
  PRIVATE ${KEYSTONE_SDK_DIR}/include/host
  PRIVATE ${KEYSTONE_SDK_DIR}/include/edge
  PRIVATE ${KEYSTONE_SDK_DIR}/include/verifier
  PRIVATE host)

add_eyrie_runtime(${eapp_target}-eyrie
  ${eyrie_plugins}
  ${eyrie_files_to_copy})

add_keystone_package(${eapp_target}-package
  ${package_name}
  ${package_script}
  ${eyrie_files_to_copy}
  ${eapp_target}
  ${package_runner_target}
  ${server_target}
  ${ca_target})

add_dependencies(${eapp_target}-package ${eapp_target}-eyrie)

add_custom_target(openclaw-keystone-artifacts ALL
  DEPENDS ${ca_target} ${server_target} ${package_runner_target} ${eapp_target}-package)
