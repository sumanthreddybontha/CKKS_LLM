#!/bin/bash

# === CONFIGURATION ===
SEAL_DIR="$HOME/Desktop/CKKS_LLM/SEAL"
SEAL_INCLUDE_DIR="$SEAL_DIR/native/src"
SEAL_CONFIG_INCLUDE="$SEAL_DIR/build/native/src"      # Contains config.h
SEAL_GSL_INCLUDE="$HOME/GSL/include"
SEAL_LIB="$SEAL_DIR/build/lib/libseal-4.1.a"

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
            -I"$SEAL_CONFIG_INCLUDE" \
            -I"$SEAL_GSL_INCLUDE" \
            "$SEAL_LIB" \
            -o "$binary" 2> /tmp/compile_error.txt

        if [ $? -eq 0 ]; then
          compiles="YES"
          echo "🚀 Running..."
          output=$(gtimeout 10s "$binary" 2>&1)
          if [ $? -eq 0 ]; then
            runs="YES"
            clean_output=$(echo "$output" | tr '\n' ' ' | sed 's/"/'\''/g')
            echo "$llm,$task,$technique,$filename,$compiles,$runs,\"$clean_output\"" >> "$REPORT_FILE"
          else
            runs="NO"
            runtime_error=$(echo "$output" | tr '\n' ' ' | sed 's/"/'\''/g')
            echo "$llm,$task,$technique,$filename,$compiles,$runs,\"$runtime_error\"" >> "$REPORT_FILE"
          fi
        else
          compiles="NO"
          compile_error=$(cat /tmp/compile_error.txt | tr '\n' ' ' | sed 's/"/'\''/g')
          echo "$llm,$task,$technique,$filename,$compiles,NO,\"$compile_error\"" >> "$REPORT_FILE"
        fi
      done
    done
  done
done

echo "✅ Evaluation complete. Results saved to $REPORT_FILE."
