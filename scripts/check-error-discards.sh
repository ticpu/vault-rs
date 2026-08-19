#!/usr/bin/env bash
# Fails on any error discard that does not say why it is safe.
#
# rustqual's ERROR_HANDLING rule reports zero on this tree with every one of
# these present, so it cannot gate them. The exemption is a `// discard-ok:
# <reason>` comment on the line or within the three above it — enough to cover
# a marker sitting above a multi-line chain, close enough to stay at the site
# rather than in a list that drifts from the code and that a reviewer never
# sees while reading the discard.
#
# Ambiguous forms are excluded on purpose. `unwrap_or(` and
# `unwrap_or_default()` exist on Option too and grep cannot tell them apart,
# so including them would mint dozens of exemptions reading "this is an
# Option", which teaches reviewers to scroll past the marker.
set -euo pipefail

cd "$(dirname "$0")/.."

PATTERNS='Err\(_\)|map_err\(\|_\||unwrap_or_else\(\|_\||let _ = |if let Ok\(|while let Ok\(|\.ok\(\)'

shopt -s nullglob
src_dirs=(crates/*/src)
if [ ${#src_dirs[@]} -eq 0 ]; then
	echo "no crates/*/src directories found" >&2
	exit 1
fi

set +e
matches=$(grep -rnE "$PATTERNS" "${src_dirs[@]}")
grep_status=$?
set -e
if [ "$grep_status" -gt 1 ]; then
	echo "grep failed scanning ${src_dirs[*]}" >&2
	exit 1
fi

failed=0
while IFS=: read -r file line _; do
	[ -n "$file" ] || continue
	before=$((line - 3))
	[ "$before" -ge 1 ] || before=1
	if sed -n "${before},${line}p" "$file" | grep -q 'discard-ok:'; then
		continue
	fi
	printf '%s:%s: error discard with no // discard-ok: reason\n' "$file" "$line"
	failed=1
done <<< "$matches"

if [ "$failed" -ne 0 ]; then
	echo
	echo 'Handle the error, or annotate the site:  // discard-ok: <why this is safe>'
	exit 1
fi
