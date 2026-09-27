cmake_minimum_required(VERSION 3.16)

project(ArduinoMDNSHostTests LANGUAGES C CXX)

enable_testing()

add_executable(
  arduino-mdns-parser-test
  mdns/ArduinoMdnsParserTest.cpp
  ../../MDNS.cpp
  ../../utility/EthernetUtil.c
)

target_compile_features(arduino-mdns-parser-test PRIVATE cxx_std_11)
target_include_directories(
  arduino-mdns-parser-test
  PRIVATE
    mdns/stubs
    ../..
)
target_compile_options(
  arduino-mdns-parser-test
  PRIVATE
    -O1
    -g
    -Wall
    -Wextra
    -Werror
    -fsanitize=address,undefined
    -fno-omit-frame-pointer
)
target_link_options(
  arduino-mdns-parser-test
  PRIVATE
    -Wl,--wrap=malloc
    -fsanitize=address,undefined
    -fno-omit-frame-pointer
)

add_test(NAME arduino-mdns-parser-test COMMAND arduino-mdns-parser-test)
