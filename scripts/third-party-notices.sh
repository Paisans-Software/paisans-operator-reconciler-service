#!/bin/sh
# Print the license and notice files of the Go standard library and of every
# third-party module linked into the given packages, for shipping beside a
# binary built from them.
#
# Usage: scripts/third-party-notices.sh [package ...] > THIRD_PARTY_NOTICES
#
# The packages default to ., the operator reconciler. The list is the packages actually linked,
# from `go list -deps`, not every module in go.mod, and it honours GOOS and
# GOARCH, so run it for the platform the binary is built for. For each linked
# package it takes the LICENSE, COPYING and NOTICE files in the package's own
# directory and every directory above it up to its module's root, so a package
# carrying a license of its own is covered as well as its module. A module with
# no license file at all is an error: its terms are unknown, and shipping it
# would be guessing.
set -eu

[ $# -gt 0 ] || set -- .

tab=$(printf '\t')
files=$(mktemp)
trap 'rm -f "$files"' EXIT

go list -deps -f '{{with .Module}}{{if not .Main}}{{.Path}}@{{.Version}}{{"\t"}}{{.Dir}}{{"\t"}}{{$.Dir}}{{end}}{{end}}' "$@" |
	sort -u |
	while IFS="$tab" read -r mod root dir; do
		while :; do
			for f in "$dir"/*; do
				case ${f##*/} in
				LICENSE* | LICENCE* | COPYING* | NOTICE* | License* | license*)
					[ -f "$f" ] && printf '%s\t%s\n' "$mod" "$f" ;;
				esac
			done
			[ "$dir" = "$root" ] && break
			dir=$(dirname "$dir")
		done
	done | sort -u >"$files"

missing=$(go list -deps -f '{{with .Module}}{{if not .Main}}{{.Path}}@{{.Version}}{{end}}{{end}}' "$@" |
	sort -u | while read -r mod; do
		grep -q "^$mod$tab" "$files" || echo "$mod"
	done)
if [ -n "$missing" ]; then
	echo "no license file found for:" >&2
	echo "$missing" >&2
	exit 1
fi

echo "The operator reconciler is licensed AGPL-3.0-or-later; see LICENSE."
echo "It links the Go standard library and the third-party modules below, under"
echo "the terms that follow each."
printf '\n================================================================\n%s\n================================================================\n\n' "Go standard library $(go env GOVERSION)"
# Homebrew's Go keeps it one directory above GOROOT.
goroot=$(go env GOROOT)
for f in "$goroot/LICENSE" "$goroot/../LICENSE" ""; do
	[ -n "$f" ] || { echo "no LICENSE for the Go standard library near $goroot" >&2; exit 1; }
	[ -f "$f" ] && { cat "$f"; break; }
done
mod_prev=
while IFS="$tab" read -r mod f; do
	if [ "$mod" != "$mod_prev" ]; then
		printf '\n================================================================\n%s\n================================================================\n' "$mod"
		mod_prev=$mod
	fi
	printf '\n--- %s\n\n' "${f#*@*/}"
	cat "$f"
done <"$files"
