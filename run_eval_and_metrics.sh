#!/bin/bash

# === CONFIGURATION ===
SEAL_INCLUDE_DIR="$HOME/SEAL/native/src"
SEAL_EXTRA_INCLUDE="$HOME/SEAL/build/native/include"
SEAL_GSL_INCLUDE="$HOME/GSL/include"
SEAL_LIB="$HOME/SEAL/build/lib/libseal-4.1.a"

BASE_DIR="codes"
REPORT_DIR="report"
REPORT_FILE="$REPORT_DIR/compilation_results_seal.csv"

mkdir -p "$REPORT_DIR"
echo "LLM,Task,Technique,Filename,Compiles,Runs,Output" > "$REPORT_FILE"

# === EVALUATION ===
for llm in $(ls "$BASE_DIR"); do
  for task in $(ls "$BASE_DIR/$llm"); do
    for technique in $(ls "$BASE_DIR/$llm/$task"); do
      for file in "$BASE_DIR/$llm/$task/$technique"/*.cpp; do
        filename=$(basename -- "$file")
        binary="/tmp/${filename%.cpp}"

        echo "🔧 Compiling: $file"
        g++ "$file" -std=c++17 \
            -I"$SEAL_INCLUDE_DIR" \
            -I"$SEAL_INCLUDE_DIR/seal" \
            -I"$SEAL_EXTRA_INCLUDE" \
            -I"$SEAL_GSL_INCLUDE" \
            "$SEAL_LIB" \
            -o "$binary" 2> /tmp/compile_error.txt

        if [ $? -eq 0 ]; then
          compiles="YES"
          echo "🚀 Running..."
          output=$(timeout 10s "$binary" 2>&1)
          if [ $? -eq 0 ]; then
            runs="YES"
            echo "$llm,$task,$technique,$filename,$compiles,$runs,\"$output\"" >> "$REPORT_FILE"
          else
            runs="NO"
            echo "$llm,$task,$technique,$filename,$compiles,$runs,ERROR" >> "$REPORT_FILE"
          fi
        else
          compiles="NO"
          echo "$llm,$task,$technique,$filename,$compiles,NO,COMPILATION_FAILED" >> "$REPORT_FILE"
        fi
      done
    done
  done
done

echo "✅ Evaluation complete. Results saved to $REPORT_FILE."
