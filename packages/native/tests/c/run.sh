#!/bin/sh
# Builds the static library and runs C programs linked against it: every lease vector, and the license
# client (Linux, macOS).
set -eu
cd "$(dirname "$0")/../.."
cargo build --release --quiet
cargo run --release --quiet --example vectors_tsv > target/vectors.tsv
libs="-lpthread -ldl -lm"
[ "$(uname)" = Darwin ] && libs="-framework IOKit -framework CoreFoundation"
cc -std=c99 -Wall -Wextra -Werror -Iinclude tests/c/verify.c target/release/libseal_native.a $libs -o target/c-verify
target/c-verify target/vectors.tsv
cc -std=c99 -Wall -Wextra -Werror -Iinclude tests/c/client.c target/release/libseal_native.a $libs -o target/c-client
storage=$(mktemp -d)
target/c-client "$storage"
rm -rf "$storage"
