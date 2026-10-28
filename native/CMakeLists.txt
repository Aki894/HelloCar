cmake_minimum_required(VERSION 3.18)
project(hellocar_hichain C)
set(CMAKE_C_STANDARD 11)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
if(NOT DEFINED SOURCE_ROOT)
  message(FATAL_ERROR "SOURCE_ROOT must point to pinned external sources")
endif()
set(AUTH "${SOURCE_ROOT}/deviceauth/frameworks/deviceauth_lite/source")
set(HUKS "${SOURCE_ROOT}/huks/frameworks/huks_lite/source/hw_keystore_sdk")
set(SECUREC "${SOURCE_ROOT}/securec")
file(GLOB_RECURSE AUTH_C CONFIGURE_DEPENDS "${AUTH}/*.c")
file(GLOB_RECURSE HUKS_C CONFIGURE_DEPENDS "${HUKS}/*.c")
file(GLOB SECUREC_C CONFIGURE_DEPENDS "${SECUREC}/src/*.c")
if(NOT AUTH_C OR NOT HUKS_C OR NOT SECUREC_C)
  message(FATAL_ERROR "Missing pinned native sources")
endif()
find_package(OpenSSL REQUIRED COMPONENTS Crypto)
find_path(CJSON_INCLUDE cJSON.h PATH_SUFFIXES cjson REQUIRED)
find_library(CJSON_LIB cjson REQUIRED)
find_library(MBEDCRYPTO_LIB mbedcrypto REQUIRED)
add_library(hellocar_hichain SHARED compat.c ${AUTH_C} ${HUKS_C} ${SECUREC_C})
target_include_directories(hellocar_hichain PRIVATE
  "${SOURCE_ROOT}/huks/interfaces/innerkits/huks_lite" "${HUKS}/.."
  compat "${SECUREC}/include" "${SOURCE_ROOT}/deviceauth/interfaces/innerkits/deviceauth_lite"
  "${AUTH}/base" "${AUTH}/auth_info" "${AUTH}/huks_adapter" "${AUTH}/json"
  "${AUTH}/key_agreement" "${AUTH}/log" "${AUTH}/schedule" "${AUTH}/struct"
  "${SOURCE_ROOT}/huks/interfaces/innerkits/huks_lite" "${HUKS}" "${HUKS}/common"
  "${HUKS}/soft_service" "${CJSON_INCLUDE}")
target_compile_definitions(hellocar_hichain PRIVATE _CUT_LOG_ _POSIX_C_SOURCE=200809L)
target_link_libraries(hellocar_hichain PRIVATE OpenSSL::Crypto "${CJSON_LIB}" "${MBEDCRYPTO_LIB}")
set_target_properties(hellocar_hichain PROPERTIES BUILD_RPATH "$ORIGIN" INSTALL_RPATH "$ORIGIN")
target_link_options(hellocar_hichain PRIVATE -Wl,--no-undefined)
