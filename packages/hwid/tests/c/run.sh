#!/bin/sh
# Builds the static library and links a C program against it (Linux, macOS).
set -eu
cd "$(dirname "$0")/../.."
cargo build --release --quiet
libs="-lpthread -ldl -lm"
[ "$(uname)" = Darwin ] && libs="-framework IOKit -framework CoreFoundation"
cc -std=c99 -Wall -Wextra -Werror -Iinclude tests/c/collect.c target/release/libseal_hwid.a $libs -o target/c-collect
target/c-collect
