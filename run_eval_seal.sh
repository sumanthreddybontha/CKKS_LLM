#!/bin/bash

# === CONFIGURATION ===
SEAL_INCLUDE_DIR="$HOME/SEAL/native/src"
SEAL_EXTRA_INCLUDE="$HOME/SEAL/build/native/include"
SEAL_BUILD_SRC="$HOME/SEAL/build/native/src"
SEAL_GSL_INCLUDE="$HOME/GSL/include"
SEAL_LIB="$HOME/SEAL/build/lib/libseal-4.1.a"

BASE_DIR="codes"
REPORT_DIR="report"
LOG_DIR="logs"
REPORT_FILE="$REPORT_DIR/compilation_results_seal.csv"

mkdir -p "$REPORT_DIR"
mkdir -p "$LOG_DIR"
echo "LLM,Task,Technique,Filename,Compiles,Runs,Output" > "$REPORT_FILE"

# === EVALUATION ===
for llm in $(ls "$BASE_DIR"); do
  for task in $(ls "$BASE_DIR/$llm"); do
    for technique in $(ls "$BASE_DIR/$llm/$task"); do
      for file in "$BASE_DIR/$llm/$task/$technique"/*.cpp; do
        filename=$(basename -- "$file")
        binary="/tmp/${filename%.cpp}"
        log_base="$LOG_DIR/${filename%.cpp}"

        echo "🔧 Compiling: $file"
        echo "Command: g++ \"$file\" -std=c++17 ..." > "$log_base.compile.txt"

        g++ "$file" -std=c++17 \
          -I"$SEAL_INCLUDE_DIR" \
          -I"$SEAL_INCLUDE_DIR/seal" \
          -I"$SEAL_EXTRA_INCLUDE" \
          -I"$SEAL_BUILD_SRC" \
          -I"$SEAL_GSL_INCLUDE" \
          $SEAL_LIB \
          -o "$binary" 2>> "$log_base.compile.txt"

        if [ $? -eq 0 ]; then
          compiles="YES"
          echo "🚀 Running..."
          output=$(gtimeout 10s "$binary" 2>> "$log_base.run.txt")
          if [ $? -eq 0 ]; then
            runs="YES"
            clean_output=$(echo "$output" | tr '\n' ' ' | sed 's/  */ /g' | cut -c1-120)
            echo "$llm,$task,$technique,$filename,$compiles,$runs,\"$clean_output\"" >> "$REPORT_FILE"

          else
            runs="NO"
            errlog=$(cat "$log_base.run.txt" | tail -n 1)
            echo "$llm,$task,$technique,$filename,$compiles,$runs,\"$errlog\"" >> "$REPORT_FILE"
          fi
        else
          compiles="NO"
          errlog=$(cat "$log_base.compile.txt" | tail -n 1)
          echo "$llm,$task,$technique,$filename,$compiles,NO,\"$errlog\"" >> "$REPORT_FILE"
        fi
      done
    done
  done
done

echo "✅ Evaluation complete. Results saved to $REPORT_FILE"
