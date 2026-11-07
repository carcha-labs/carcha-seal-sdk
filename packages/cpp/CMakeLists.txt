# Carcha Seal for C++: builds the native library (../native, Rust) as a static library and provides the
# CarchaSeal::seal target: the header-only wrapper (include/carcha/seal.hpp), the C header and the static
# library with the system libraries it needs.
#
#   add_subdirectory(carcha-seal-sdk/packages/cpp)
#   target_link_libraries(my_app PRIVATE CarchaSeal::seal)
#
# Needs a Rust toolchain (cargo) on PATH.
cmake_minimum_required(VERSION 3.16)
project(CarchaSeal VERSION 0.1.0 LANGUAGES CXX)

option(CARCHA_SEAL_HTTP "Build the native library with its built-in HTTP client" ON)
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  set(carcha_seal_top_level ON)
else()
  set(carcha_seal_top_level OFF)
endif()
option(CARCHA_SEAL_TESTS "Build the tests and the example" ${carcha_seal_top_level})

find_program(CARGO cargo)
if(NOT CARGO)
  message(FATAL_ERROR "Carcha Seal: cargo (the Rust toolchain) was not found on PATH")
endif()

set(native_dir "${CMAKE_CURRENT_SOURCE_DIR}/../native")
set(cargo_target "${CMAKE_CURRENT_BINARY_DIR}/cargo")
set(cargo_args rustc --release --lib --crate-type staticlib --manifest-path "${native_dir}/Cargo.toml" --target-dir "${cargo_target}")
if(CARCHA_SEAL_HTTP)
  list(APPEND cargo_args --features http)
endif()
if(MSVC)
  set(native_lib "${cargo_target}/release/seal_native.lib")
else()
  set(native_lib "${cargo_target}/release/libseal_native.a")
endif()

# The system libraries a Rust static library needs differ by platform; rustc prints them
# (--print native-static-libs) when it builds the library, so they are read, not guessed.
if(NOT CARCHA_SEAL_NATIVE_LIBS)
  foreach(attempt 1 2)
    execute_process(COMMAND "${CARGO}" ${cargo_args} -- --print native-static-libs
                    RESULT_VARIABLE build_result ERROR_VARIABLE build_log OUTPUT_QUIET)
    if(NOT build_result EQUAL 0)
      message(FATAL_ERROR "Carcha Seal: building the native library failed:\n${build_log}")
    endif()
    string(REGEX MATCH "native-static-libs: ([^\r\n]*)" found "${build_log}")
    if(found)
      break()
    endif()
    # Already built, so rustc printed nothing: rebuild the library once to read the list.
    execute_process(COMMAND "${CARGO}" clean -p seal_native --release --manifest-path "${native_dir}/Cargo.toml" --target-dir "${cargo_target}" OUTPUT_QUIET ERROR_QUIET)
  endforeach()
  if(NOT found)
    message(FATAL_ERROR "Carcha Seal: rustc did not print the native static libraries")
  endif()
  string(STRIP "${CMAKE_MATCH_1}" printed)
  separate_arguments(printed_list NATIVE_COMMAND "${printed}")
  set(libs "")
  set(framework OFF)
  foreach(item IN LISTS printed_list)
    if(framework)
      list(APPEND libs "-framework ${item}")
      set(framework OFF)
    elseif(item STREQUAL "-framework")
      set(framework ON)
    elseif(item MATCHES "^-l(.+)$")
      list(APPEND libs "${CMAKE_MATCH_1}")
    elseif(NOT item MATCHES "^/")
      list(APPEND libs "${item}")
    endif()
  endforeach()
  list(REMOVE_DUPLICATES libs)
  set(CARCHA_SEAL_NATIVE_LIBS "${libs}" CACHE STRING "System libraries the Carcha Seal native library needs (from rustc)")
endif()

# Rebuilt on every build (cargo returns at once when nothing changed).
add_custom_target(carcha_seal_native_build ALL
  COMMAND "${CARGO}" ${cargo_args}
  BYPRODUCTS "${native_lib}"
  COMMENT "Building the Carcha Seal native library"
  VERBATIM)

add_library(carcha_seal_native STATIC IMPORTED GLOBAL)
set_target_properties(carcha_seal_native PROPERTIES
  IMPORTED_LOCATION "${native_lib}"
  INTERFACE_INCLUDE_DIRECTORIES "${native_dir}/include"
  INTERFACE_LINK_LIBRARIES "${CARCHA_SEAL_NATIVE_LIBS}")
add_dependencies(carcha_seal_native carcha_seal_native_build)

add_library(carcha_seal INTERFACE)
add_library(CarchaSeal::seal ALIAS carcha_seal)
target_include_directories(carcha_seal INTERFACE "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_compile_features(carcha_seal INTERFACE cxx_std_17)
target_link_libraries(carcha_seal INTERFACE carcha_seal_native)
if(CARCHA_SEAL_HTTP)
  target_compile_definitions(carcha_seal INTERFACE SEAL_HAS_HTTP)
endif()

if(CARCHA_SEAL_TESTS)
  enable_testing()
  add_executable(seal_cli examples/seal_cli.cpp)
  target_link_libraries(seal_cli PRIVATE CarchaSeal::seal)

  add_executable(seal_scenarios tests/scenarios.cpp)
  target_link_libraries(seal_scenarios PRIVATE CarchaSeal::seal)
  if(MSVC)
    target_compile_options(seal_scenarios PRIVATE /W4)
  else()
    target_compile_options(seal_scenarios PRIVATE -Wall -Wextra -Werror)
  endif()
  set(scenarios_tsv "${CMAKE_CURRENT_BINARY_DIR}/scenarios.tsv")
  add_custom_command(OUTPUT "${scenarios_tsv}"
    COMMAND "${CARGO}" run --quiet --release --example scenarios_tsv --manifest-path "${CMAKE_CURRENT_SOURCE_DIR}/../client/Cargo.toml" --target-dir "${cargo_target}" > "${scenarios_tsv}"
    DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/../client/tests/vectors.json" "${CMAKE_CURRENT_SOURCE_DIR}/../client/examples/scenarios_tsv.rs"
    COMMENT "Writing the client scenarios for the C++ test")
  add_custom_target(carcha_seal_scenarios ALL DEPENDS "${scenarios_tsv}")
  add_test(NAME scenarios COMMAND seal_scenarios "${scenarios_tsv}" "${CMAKE_CURRENT_BINARY_DIR}/scenario-storage")

  add_executable(seal_threads tests/threads.cpp)
  find_package(Threads REQUIRED)
  target_link_libraries(seal_threads PRIVATE CarchaSeal::seal Threads::Threads)
  if(MSVC)
    target_compile_options(seal_threads PRIVATE /W4)
  else()
    target_compile_options(seal_threads PRIVATE -Wall -Wextra -Werror)
  endif()
  add_test(NAME threads COMMAND seal_threads "${CMAKE_CURRENT_BINARY_DIR}/threads-storage")
endif()
