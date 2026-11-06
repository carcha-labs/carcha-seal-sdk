#!/bin/sh
# Builds the static library and runs a C program linked against it over every lease vector
# (Linux, macOS).
set -eu
cd "$(dirname "$0")/../.."
cargo build --release --quiet
cargo run --release --quiet --example vectors_tsv > target/vectors.tsv
libs="-lpthread -ldl -lm"
[ "$(uname)" = Darwin ] && libs="-framework IOKit -framework CoreFoundation"
cc -std=c99 -Wall -Wextra -Werror -Iinclude tests/c/verify.c target/release/libseal_native.a $libs -o target/c-verify
target/c-verify target/vectors.tsv
