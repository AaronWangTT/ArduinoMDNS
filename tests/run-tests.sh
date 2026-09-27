#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

CXX="${CXX:-g++}"
build="${MDNS_BUILD_DIR:-$(mktemp -d -t arduino-mdns-tests.XXXXXXXX)}"
mkdir -p "$build"
sourceRoot=.
if [[ "${MDNS_BASELINE_ONLY:-0}" == 1 ]]; then
   sourceRoot="$build/baseline"
   mkdir -p "$sourceRoot"
   git archive 394dca9dc4d5f1eb20140d524c8b2f2366a53cfa MDNS.cpp MDNS.h utility |
      tar -x -C "$sourceRoot"
fi
flags=(-std=c++11 -Wall -Wextra -Wpedantic -g -O1
       -fno-omit-frame-pointer -fsanitize=address,undefined
       -fno-sanitize-recover=all "-I$sourceRoot" -Itests/host)
sources=("$sourceRoot/MDNS.cpp")
if [[ -f "$sourceRoot/utility/DnsPacket.cpp" ]]; then
   sources+=("$sourceRoot/utility/DnsPacket.cpp")
fi
"${CC:-gcc}" -g -O1 -fsanitize=address,undefined -I. \
   -c utility/EthernetUtil.c -o "$build/EthernetUtil.o"

tests=(test_baseline test_dns_packet test_mdns)
if [[ "${MDNS_BASELINE_ONLY:-0}" == 1 ]]; then
   tests=(test_baseline test_legacy_baseline)
elif [[ "${MDNS_PARSER_ONLY:-0}" == 1 ]]; then
   tests=(test_dns_packet)
fi
for test in "${tests[@]}"; do
   if [[ ! -f "tests/$test.cpp" ]]; then
      if [[ "${MDNS_BASELINE_ONLY:-0}" != 1 ]]; then
         echo "Required test source missing: tests/$test.cpp" >&2
         exit 1
      fi
      continue
   fi
   if [[ "$test" == test_dns_packet ]]; then
      "$CXX" "${flags[@]}" tests/test_dns_packet.cpp utility/DnsPacket.cpp -o "$build/$test"
   else
      "$CXX" "${flags[@]}" "tests/$test.cpp" "${sources[@]}" \
         "$build/EthernetUtil.o" -o "$build/$test"
   fi
   ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1 "$build/$test"
done
echo "Host sanitizer tests passed. Build artifacts: $build"
