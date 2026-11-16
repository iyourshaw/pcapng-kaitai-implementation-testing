# Builds the C++ code that ksc generates from pcapng.ksy and decodes every
# sample with it. scripts/compile.py writes the generated code:
#   generated/    -t cpp_stl --cpp-standard 11: built as C++11 and decode-tested
#   generated98/  -t cpp_stl --cpp-standard 98: built as real C++98 (build check only)
# Run it through tests/cpp/run.sh (on Linux, or in WSL on Windows).

cmake_minimum_required(VERSION 3.24)
project(pcapng_kaitai_cpp_tests CXX)

include(FetchContent)
set(FETCHCONTENT_QUIET ON)

# Pinned tarballs (sha256-checked, so no git is needed).
FetchContent_Declare(kaitai_runtime
  URL https://github.com/kaitai-io/kaitai_struct_cpp_stl_runtime/archive/refs/tags/0.11.tar.gz
  URL_HASH SHA256=55f62b0d97e9f8df6db4e4577c6343d6ad95705a4ce6437bf25bf184c06840d2
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE
  # Download only: the runtime is compiled below, not through its own CMakeLists,
  # because it's needed twice (as C++11 for generated/, as C++98 for generated98/).
  SOURCE_SUBDIR not-a-cmake-project)
FetchContent_Declare(googletest
  URL https://github.com/google/googletest/releases/download/v1.18.0/googletest-1.18.0.tar.gz
  URL_HASH SHA256=6e3191c1455468b3fc35a417fb565c1c5071aee1b7e7f85e30cf48a98d37d8b5
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
FetchContent_Declare(nlohmann_json
  URL https://github.com/nlohmann/json/releases/download/v3.12.0/json.tar.xz
  URL_HASH SHA256=42f6e95cad6ec532fd372391373363b62a14af6d771056dbfc86160e6dfff7aa
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE)

set(BUILD_GMOCK ON CACHE BOOL "" FORCE)
set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(kaitai_runtime googletest nlohmann_json)

find_package(Iconv REQUIRED)

# Warnings are reported but don't fail the build (the build check prints them).
# -Wno-long-long as in the runtime's own build: it uses long long on purpose,
# even for C++98.
set(GENERATED_WARNINGS -Wall -Wextra -Wpedantic -Wno-long-long)

function(add_formats_library name standard source_dir)
  add_library(${name}_runtime STATIC ${kaitai_runtime_SOURCE_DIR}/kaitai/kaitaistream.cpp)
  target_include_directories(${name}_runtime PUBLIC ${kaitai_runtime_SOURCE_DIR})
  target_compile_definitions(${name}_runtime PRIVATE KS_STR_ENCODING_ICONV)
  target_link_libraries(${name}_runtime PRIVATE Iconv::Iconv)
  set_target_properties(${name}_runtime PROPERTIES
    CXX_STANDARD ${standard} CXX_STANDARD_REQUIRED ON CXX_EXTENSIONS OFF)

  file(GLOB sources CONFIGURE_DEPENDS ${source_dir}/*.cpp)
  if(NOT sources)
    message(FATAL_ERROR "no generated C++ in ${source_dir}; run: python scripts/compile.py --target cpp")
  endif()
  add_library(${name} STATIC ${sources})
  target_include_directories(${name} PUBLIC ${source_dir})
  target_link_libraries(${name} PUBLIC ${name}_runtime)
  target_compile_options(${name} PUBLIC ${GENERATED_WARNINGS})
  set_target_properties(${name} PROPERTIES
    CXX_STANDARD ${standard} CXX_STANDARD_REQUIRED ON CXX_EXTENSIONS OFF)
endfunction()

add_formats_library(formats 11 ${CMAKE_CURRENT_SOURCE_DIR}/generated)
add_formats_library(formats98 98 ${CMAKE_CURRENT_SOURCE_DIR}/generated98)

# GoogleTest needs C++17. The generated code stays C++11; only the tests are C++17.
add_executable(pcapng_tests test_samples.cpp pcapng_summary.cpp)
target_link_libraries(pcapng_tests PRIVATE formats GTest::gmock_main nlohmann_json::nlohmann_json)
target_compile_options(pcapng_tests PRIVATE -Wall -Wextra)
set_target_properties(pcapng_tests PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED ON CXX_EXTENSIONS OFF)
# Default sample and golden-file locations; PCAPNG_SAMPLES_DIR / PCAPNG_EXPECTED_DIR override them.
get_filename_component(REPO_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../.. ABSOLUTE)
target_compile_definitions(pcapng_tests PRIVATE PCAPNG_REPO_DIR="${REPO_DIR}")
