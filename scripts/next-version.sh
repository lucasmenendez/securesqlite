#!/usr/bin/env bash
# Copyright (C) 2026 Lucas Menendez
# SPDX-License-Identifier: AGPL-3.0-only

set -euo pipefail

# Compute the next release tag from git tags and pull-request labels.
#
# Input:
#   LABELS_JSON  JSON array of label names (required; defaults to "[]")
#   GITHUB_OUTPUT  optional file to append step outputs to
#
# Output keys: skip, tag, prerelease, previous

labels_json=${LABELS_JSON:-'[]'}
if ! labels=$(jq -r '.[]' <<<"$labels_json" 2>/dev/null); then
  echo "LABELS_JSON is not a JSON array" >&2
  exit 1
fi

has_label() {
  grep -qx -- "$1" <<<"$labels"
}

emit() {
  local skip=$1
  if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    {
      echo "skip=$skip"
      echo "tag=${tag:-}"
      echo "prerelease=${prerelease:-false}"
      echo "previous=${previous:-}"
    } >>"$GITHUB_OUTPUT"
  else
    printf 'skip=%s\ntag=%s\nprerelease=%s\nprevious=%s\n' \
      "$skip" "${tag:-}" "${prerelease:-false}" "${previous:-}"
  fi
}

kind=""
if has_label release; then
  kind=release
elif has_label release-candidate; then
  kind=release-candidate
else
  emit true
  exit 0
fi

if has_label release && has_label release-candidate; then
  echo "::warning::Both release and release-candidate labels are present; treating as release" >&2
fi

bump=patch
bump_count=0
for candidate in major minor patch; do
  if has_label "bump:$candidate"; then
    bump=$candidate
    bump_count=$((bump_count + 1))
  fi
done
if ((bump_count > 1)); then
  echo "conflicting bump:* labels" >&2
  exit 1
fi

override=""
override_count=0
while IFS= read -r label; do
  case "$label" in
  version:*)
    v=${label#version:}
    v=${v#v}
    if [[ ! "$v" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      echo "invalid version label: $label" >&2
      exit 1
    fi
    override=$v
    override_count=$((override_count + 1))
    ;;
  esac
done <<<"$labels"
if ((override_count > 1)); then
  echo "multiple version:* labels" >&2
  exit 1
fi

version_gt() {
  local a=$1 b=$2
  IFS=. read -r ax ay az <<<"$a"
  IFS=. read -r bx by bz <<<"$b"
  ax=$((10#$ax))
  ay=$((10#$ay))
  az=$((10#$az))
  bx=$((10#$bx))
  by=$((10#$by))
  bz=$((10#$bz))
  if ((ax != bx)); then
    ((ax > bx))
    return
  fi
  if ((ay != by)); then
    ((ay > by))
    return
  fi
  ((az > bz))
}

bump_version() {
  local base=$1 which=$2
  IFS=. read -r x y z <<<"$base"
  case "$which" in
  major) echo "$((10#$x + 1)).0.0" ;;
  minor) echo "$((10#$x)).$((10#$y + 1)).0" ;;
  patch) echo "$((10#$x)).$((10#$y)).$((10#$z + 1))" ;;
  esac
}

git fetch --tags --force >/dev/null 2>&1 || true

stable=""
rc=""
while IFS= read -r tag; do
  [[ -n "$tag" ]] || continue
  if [[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    [[ -z "$stable" ]] && stable=$tag
  elif [[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+-rc[0-9]+$ ]]; then
    [[ -z "$rc" ]] && rc=$tag
  fi
  [[ -n "$stable" && -n "$rc" ]] && break
done < <(git tag -l 'v*' --sort=-v:refname)

stable_base=${stable#v}
stable_base=${stable_base:-0.0.0}
rc_base=""
rc_num=0
if [[ -n "$rc" ]]; then
  rc_base=${rc#v}
  rc_num=${rc_base##*-rc}
  rc_base=${rc_base%%-rc*}
fi

active_base=""
if [[ -z "$override" ]]; then
  while IFS= read -r tag; do
    [[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+-rc[0-9]+$ ]] || continue
    base=${tag#v}
    base=${base%%-rc*}
    if version_gt "$base" "$stable_base"; then
      if [[ -n "$active_base" && "$active_base" != "$base" ]]; then
        echo "multiple active release-candidate bases above $stable_base: $active_base and $base" >&2
        exit 1
      fi
      active_base=$base
    fi
  done < <(git tag -l 'v*' --sort=-v:refname)
fi

base=""
if [[ -n "$override" ]]; then
  if ! version_gt "$override" "$stable_base"; then
    if [[ "$kind" == "release" ]] && git rev-parse -q --verify "refs/tags/v$override" >/dev/null; then
      :
    else
      echo "version:$override must be greater than latest stable $stable_base" >&2
      exit 1
    fi
  fi
  base=$override
elif [[ "$kind" == "release" ]]; then
  if [[ -n "$active_base" ]]; then
    base=$active_base
  elif [[ -z "$stable" ]]; then
    base=0.1.0
  else
    base=$(bump_version "$stable_base" patch)
  fi
else
  if [[ -n "$active_base" ]]; then
    base=$active_base
  elif [[ -z "$stable" ]]; then
    if [[ "$bump" == "major" ]]; then
      base=1.0.0
    else
      base=0.1.0
    fi
  else
    base=$(bump_version "$stable_base" "$bump")
  fi
fi

if [[ "$kind" == "release" ]]; then
  tag="v$base"
  prerelease=false
else
  n=1
  if [[ -n "$rc" && "$base" == "$rc_base" ]]; then
    n=$((10#$rc_num + 1))
  fi
  tag="v$base-rc$n"
  prerelease=true
fi

previous=""
if [[ "$kind" == "release" ]]; then
  while IFS= read -r t; do
    [[ "$t" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || continue
    tb=${t#v}
    if version_gt "$base" "$tb"; then
      previous=$t
      break
    fi
  done < <(git tag -l 'v*' --sort=-v:refname)
else
  while IFS= read -r t; do
    [[ "$t" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-rc[0-9]+)?$ ]] || continue
    [[ "$t" == "$tag" ]] && continue
    tb=${t#v}
    tb=${tb%%-rc*}
    if [[ "$tb" == "$base" ]] || version_gt "$base" "$tb"; then
      previous=$t
      break
    fi
  done < <(git tag -l 'v*' --sort=-v:refname)
fi

emit false
