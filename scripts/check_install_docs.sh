#!/bin/sh
set -eu

url='https://github.com/EntropyRoot/Qanat-Scanner.git'
expected="git clone $url Qanat-Scanner"
checks=0

for file in README.md README.fa.md CONTRIBUTING.md; do
    if [ "$(grep -Fxc "$expected" "$file" || true)" -ne 1 ]; then
        echo "FAIL $file: clone must name the Qanat-Scanner destination" >&2
        exit 1
    fi
    if grep -Fxq "git clone $url" "$file"; then
        echo "FAIL $file: implicit clone directory can disagree with cd" >&2
        exit 1
    fi
    if grep -Fxq 'cd Qanat' "$file"; then
        echo "FAIL $file: stale checkout path cd Qanat" >&2
        exit 1
    fi
    if ! grep -Fxq 'cd Qanat-Scanner' "$file"; then
        echo "FAIL $file: missing matching checkout directory" >&2
        exit 1
    fi
    if ! grep -Fxq 'make install' "$file"; then
        echo "FAIL $file: build instructions do not refresh the installed command" >&2
        exit 1
    fi
    echo "  ok    $file clone/build/install path"
    checks=$((checks + 1))
done

echo "install documentation checks: $checks ok, 0 failed"
