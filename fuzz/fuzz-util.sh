#!/usr/bin/env bash

REPO_DIR=$(git rev-parse --show-toplevel)

listTargetFiles() {
  pushd "$REPO_DIR/fuzz" > /dev/null || exit 1
  find fuzz_targets/ -type f -name "*.rs" | sort
  popd > /dev/null || exit 1
}

targetFileToName() {
  echo "$1" \
    | sed 's/^fuzz_targets\///' \
    | sed 's/\.rs$//' \
    | sed 's/\//_/g'
}

listTargetNames() {
  for target in $(listTargetFiles); do
    targetFileToName "$target"
  done
}

# Utility function to avoid CI failures on Windows
checkWindowsFiles() {
  incorrectFilenames=$(find . -type f -name "*,*" -o -name "*:*" -o -name "*<*" -o -name "*>*" -o -name "*|*" -o -name "*\?*" -o -name "*\**" -o -name "*\"*" | wc -l)
  if [ "$incorrectFilenames" -gt 0 ]; then
    echo "Bailing early because there is a Windows-incompatible filename in the tree."
    exit 2
  fi
}
