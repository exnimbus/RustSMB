#!/usr/bin/env bash
set -euo pipefail

matrix="${1:-PORTING.md}"

if [[ ! -f "$matrix" ]]; then
  echo "matrix not found: $matrix" >&2
  exit 2
fi

awk -F '|' '
  function trim(s) {
    gsub(/^[ \t]+|[ \t]+$/, "", s)
    return s
  }

  /^\| .* \| (done|partial|missing|not planned) \|/ {
    feature = trim($2)
    status = trim($3)
    evidence = trim($4)
    count[status]++
    total++

    if (status == "partial" || status == "missing") {
      bad_status = 1
      printf "%d: %s is %s\n", NR, feature, status > "/dev/stderr"
    }
    if (status == "done" && evidence !~ /`/) {
      weak_evidence = 1
      printf "%d: %s done row lacks concrete backtick evidence\n", NR, feature > "/dev/stderr"
    }
    if (status == "not planned" && evidence !~ /GoSMB/) {
      weak_exclusion = 1
      printf "%d: %s not-planned row does not cite GoSMB scope\n", NR, feature > "/dev/stderr"
    }
  }

  END {
    printf "Matrix feature rows: %d\n", total
    printf "Done rows: %d\n", count["done"] + 0
    printf "Not-planned rows: %d\n", count["not planned"] + 0
    printf "Partial rows: %d\n", count["partial"] + 0
    printf "Missing rows: %d\n", count["missing"] + 0

    if (total == 0 || bad_status || weak_evidence || weak_exclusion) {
      exit 1
    }
  }
' "$matrix"
