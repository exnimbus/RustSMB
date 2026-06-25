#!/usr/bin/env bash
set -euo pipefail

gosmb_dir="${GOSMB_DIR:-../GoSMB}"
reviewed_file="${REVIEWED_TEST_AUDIT:-tools/porting-test-reviewed.tsv}"
mode="${1:-summary}"

usage() {
  cat <<'EOF'
Usage:
  tools/porting-test-audit.sh [summary|missing|missing-source|unreviewed|unreviewed-source|matched]

Environment:
  GOSMB_DIR  Path to the GoSMB source tree. Default: ../GoSMB
  REVIEWED_TEST_AUDIT
             TSV file of reviewed normalized GoSMB test names. Default:
             tools/porting-test-reviewed.tsv

Notes:
  This is a deterministic first-pass audit. It compares normalized Go `Test...`
  names against normalized Rust test function names. A missing line is a review
  candidate, not proof the behavior is unported, because Rust tests often use
  clearer names or group several Go cases into one integration test.
EOF
}

need_rg() {
  if ! command -v rg >/dev/null 2>&1; then
    echo "rg is required" >&2
    exit 2
  fi
}

normalize() {
  tr '[:upper:]' '[:lower:]' | tr -cd '[:alnum:]\n'
}

extract_go_tests() {
  rg -o '^func Test[A-Za-z0-9_]+' \
    --glob '*_test.go' \
    "$gosmb_dir" \
    | sed 's/.*func Test//' \
    | normalize \
    | sort -u
}

extract_go_tests_with_source() {
  rg -n '^func Test[A-Za-z0-9_]+' \
    --glob '*_test.go' \
    "$gosmb_dir" \
    | awk -F: '{
        name = $0
        sub(/^.*func Test/, "", name)
        sub(/\(.*/, "", name)
        norm = tolower(name)
        gsub(/[^[:alnum:]]/, "", norm)
        print norm "\t" $1 ":" $2 "\t" name
      }' \
    | sort -u
}

extract_rust_tests() {
  rg -o '^(async )?fn [A-Za-z0-9_]+' src tests examples \
    | sed -E 's/.*fn //' \
    | normalize \
    | sort -u
}

extract_reviewed_tests() {
  if [[ ! -f "$reviewed_file" ]]; then
    return
  fi
  awk -F '\t' '
    NF && $1 !~ /^#/ {
      name = tolower($1)
      gsub(/[^[:alnum:]]/, "", name)
      if (name != "") {
        print name
      }
    }' "$reviewed_file" \
    | sort -u
}

need_rg
if [[ ! -d "$gosmb_dir" ]]; then
  echo "GoSMB source tree not found: $gosmb_dir" >&2
  exit 2
fi

go_tests="$(mktemp)"
go_meta="$(mktemp)"
rust_tests="$(mktemp)"
missing_tests="$(mktemp)"
reviewed_tests="$(mktemp)"
unreviewed_tests="$(mktemp)"
trap 'rm -f "$go_tests" "$go_meta" "$rust_tests" "$missing_tests" "$reviewed_tests" "$unreviewed_tests"' EXIT

extract_go_tests >"$go_tests"
extract_go_tests_with_source >"$go_meta"
extract_rust_tests >"$rust_tests"
comm -23 "$go_tests" "$rust_tests" >"$missing_tests"
extract_reviewed_tests >"$reviewed_tests"
comm -23 "$missing_tests" "$reviewed_tests" >"$unreviewed_tests"

case "$mode" in
  -h|--help|help)
    usage
    ;;
  summary)
    go_count="$(wc -l <"$go_tests" | tr -d ' ')"
    rust_count="$(wc -l <"$rust_tests" | tr -d ' ')"
    matched_count="$(comm -12 "$go_tests" "$rust_tests" | wc -l | tr -d ' ')"
    missing_count="$(wc -l <"$missing_tests" | tr -d ' ')"
    reviewed_count="$(comm -12 "$missing_tests" "$reviewed_tests" | wc -l | tr -d ' ')"
    unreviewed_count="$(wc -l <"$unreviewed_tests" | tr -d ' ')"
    cat <<EOF
GoSMB normalized tests: $go_count
Rust normalized tests: $rust_count
Exact normalized matches: $matched_count
Manual-review candidates: $missing_count
Reviewed renamed/grouped candidates: $reviewed_count
Unreviewed candidates: $unreviewed_count

Run tools/porting-test-audit.sh unreviewed-source to list remaining candidates.
EOF
    ;;
  missing)
    cat "$missing_tests"
    ;;
  missing-source)
    awk -F '\t' 'FNR == NR { missing[$1] = 1; next } missing[$1]' "$missing_tests" "$go_meta"
    ;;
  unreviewed)
    cat "$unreviewed_tests"
    ;;
  unreviewed-source)
    awk -F '\t' 'FNR == NR { missing[$1] = 1; next } missing[$1]' "$unreviewed_tests" "$go_meta"
    ;;
  matched)
    comm -12 "$go_tests" "$rust_tests"
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
