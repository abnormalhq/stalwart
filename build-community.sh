#!/usr/bin/env sh
set -eu

if [ "$#" -ne 0 ]; then
    printf '%s\n' 'build-community.sh does not accept Cargo overrides.' >&2
    exit 2
fi

exec cargo build --locked --release -p stalwart --no-default-features \
  --features "sqlite postgres mysql rocks s3 redis keep azure nats"
