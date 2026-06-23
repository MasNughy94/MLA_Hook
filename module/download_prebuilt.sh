#!/bin/bash
set -e

OUTDIR="${1:-$(dirname "$0")/prebuilt}"
BASE_URL="https://raw.githubusercontent.com/shadow3aaa/dobby-api/master/prebuilt/android"

ABIS=("arm64-v8a")

for abi in "${ABIS[@]}"; do
    abi_dir="$OUTDIR/$abi"
    mkdir -p "$abi_dir"

    for file in libdobby.so libdobby.a; do
        url="$BASE_URL/$abi/$file"
        echo "Downloading $url -> $abi_dir/$file"
        curl -fSL "$url" -o "$abi_dir/$file"
    done
done

echo "Done. Prebuilt libraries downloaded to $OUTDIR"
