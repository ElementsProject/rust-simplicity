#!/usr/bin/env bash

# Continuosly cycle over fuzz targets running each for 1 hour.
# It uses chrt SCHED_IDLE so that other process takes priority.

set -o errexit # exit immediately if any command fails
set -o xtrace # print trace of executed commands

REPO_DIR=$(git rev-parse --show-toplevel)
# shellcheck source=./fuzz-util.sh
source "$REPO_DIR/fuzz/fuzz-util.sh"

while :
do
  for targetFile in $(listTargetFiles); do
    targetName=$(targetFileToName "$targetFile")

    # fuzz for one hour
    chrt -i 0 cargo-fuzz run "$targetName" -- -max_total_time=3600
    # minimize the corpus
    cargo-fuzz cmin "$targetName"
  done
done

