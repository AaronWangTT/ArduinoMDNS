#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

CXX="${CXX:-clang++}"
seconds="${MDNS_FUZZ_SECONDS:-60}"
build="${MDNS_BUILD_DIR:-$(mktemp -d -t arduino-mdns-fuzz.XXXXXXXX)}"
mkdir -p "$build"
flags=(-std=c++11 -g -O1 -fno-omit-frame-pointer
       -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all
       -I. -Itests/host)
targets=(dns_packet mdns)
if [[ -n "${MDNS_FUZZ_TARGET:-}" ]]; then
   case "$MDNS_FUZZ_TARGET" in
      dns_packet|mdns) targets=("$MDNS_FUZZ_TARGET") ;;
      *) echo "Unknown fuzz target: $MDNS_FUZZ_TARGET" >&2; exit 1 ;;
   esac
fi
for target in "${targets[@]}"; do
   sources=("tests/fuzz_$target.cpp" utility/DnsPacket.cpp)
   if [[ "$target" == mdns ]]; then
      sources+=(MDNS.cpp)
   fi
   "$CXX" "${flags[@]}" "${sources[@]}" -o "$build/fuzz_$target"
   corpus="$build/corpus_$target"
   mkdir -p "$corpus"
   if [[ -d "tests/corpus/$target" ]]; then
      cp -a "tests/corpus/$target/." "$corpus/"
   fi
   printf '\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06device\x05local\x00\x00\x01\x00\x01' > "$corpus/a-query"
   printf '\x00\x00\x84\x00\x00\x00\x00\x01\x00\x00\x00\x00\x06device\x05local\x00\x00\x01\x00\x01\x00\x00\x00\x78\x00\x04\x0a\x00\x00\x01' > "$corpus/a-answer"
   printf '\x01a\x00\xc0\x00' > "$corpus/name-pointer"
   ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1 \
      "$build/fuzz_$target" "$corpus" -seed=3166 -max_len=2048 \
      "-max_total_time=$seconds" -timeout=10 -rss_limit_mb=2048 \
      "-artifact_prefix=$build/"
done
echo "Fuzz tests passed. Build artifacts: $build"
