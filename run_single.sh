#!/bin/bash

# === USAGE CHECK ===
if [ $# -ne 1 ]; then
  echo "Usage: $0 path/to/file.cpp"
  exit 1
fi

FILE="$1"
FILENAME=$(basename -- "$FILE")
BINARY="/tmp/${FILENAME%.cpp}"

# === CONFIGURATION ===
SEAL_DIR="$HOME/SEAL"
SEAL_INCLUDE_DIR="$SEAL_DIR/native/src"
SEAL_CONFIG_INCLUDE="$SEAL_DIR/build/native/src"
SEAL_GSL_INCLUDE="$HOME/GSL/include"
SEAL_LIB="$SEAL_DIR/build/lib/libseal.a"

# === COMPILATION ===
echo "🔧 Compiling: $FILE"
g++ "$FILE" -std=c++17 \
    -I"$SEAL_INCLUDE_DIR" \
    -I"$SEAL_CONFIG_INCLUDE" \
    -I"$SEAL_GSL_INCLUDE" \
    "$SEAL_LIB" \
    -o "$BINARY" 2> /tmp/compile_error.txt

if [ $? -eq 0 ]; then
  echo "✅ Compilation successful"
  echo "🚀 Running binary: $BINARY"
  output=$(gtimeout 10s "$BINARY" 2>&1)
  if [ $? -eq 0 ]; then
    echo "✅ Program ran successfully"
    echo "📤 Output:"
    echo "$output"
  else
    echo "❌ Runtime Error:"
    echo "$output"
  fi
else
  echo "❌ Compilation Failed:"
  cat /tmp/compile_error.txt
fi

echo "-------------------------------------------"
