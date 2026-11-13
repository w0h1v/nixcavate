#!/bin/bash
# Copies the files build.sh made (and the tools' own listings, the ground truth) into this folder.
# Usage: collect.sh <build-output-dir>
set -euo pipefail
cd "$(dirname "$0")"; W=$1
rm -rf tree truth; mkdir -p tree/home truth
cp -r "$W/tree/home/alice" tree/home/alice
rm -rf tree/home/alice/.npm tree/home/alice/.gitconfig
cp "$W"/*.truth.txt truth/
