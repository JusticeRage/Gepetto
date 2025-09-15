#!/usr/bin/env bash
set -euo pipefail

# Update translation template (POT), merge into existing POs, and compile MOs.
# Requirements: xgettext, msgmerge, msgfmt (GNU gettext)

ROOT_DIR="$(
  if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    git rev-parse --show-toplevel
  else
    # Fallback to directory two levels up from this script
    cd "$(dirname "$0")/.." && pwd -P
  fi
)"
cd "$ROOT_DIR"

LOCALES_DIR="gepetto/locales"
POT_FILE="$LOCALES_DIR/gepetto.pot"

need() { command -v "$1" >/dev/null 2>&1 || { echo "Error: '$1' not found in PATH." >&2; MISSING=1; }; }
MISSING=0
need xgettext
need msgmerge
need msgfmt
need msgattrib
if [ "${MISSING}" -ne 0 ]; then
  cat >&2 <<EOF
One or more gettext tools are missing.
- macOS:  brew install gettext && export PATH="$(brew --prefix gettext)/bin:\$PATH"
- Debian/Ubuntu: sudo apt-get install gettext
- Windows: use MSYS2 or GnuWin32 and ensure xgettext/msgmerge/msgfmt are in PATH
EOF
  exit 1
fi

# Build list of Python sources, excluding locale artifacts
TMP_LIST="$(mktemp -t gepetto_i18n.XXXXXX)"
trap 'rm -f "$TMP_LIST"' EXIT

if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  # Prefer git-tracked files for stability
  git ls-files '*.py' | grep -v "^gepetto/locales/" > "$TMP_LIST"
else
  # Fallback: find all python files under gepetto plus top-level gepetto.py
  find gepetto -type f -name '*.py' -not -path '*/locales/*' -print > "$TMP_LIST"
  [ -f "gepetto.py" ] && echo "gepetto.py" >> "$TMP_LIST"
fi

if [ ! -s "$TMP_LIST" ]; then
  echo "No Python files found to extract messages from." >&2
  exit 1
fi

echo "[i18n] Generating POT → $POT_FILE"
xgettext \
  --from-code=UTF-8 \
  --language=Python \
  --keyword=_ \
  --package-name="gepetto" \
  --package-version="0" \
  --add-comments \
  --files-from="$TMP_LIST" \
  --output="$POT_FILE"

echo "[i18n] Merging POT into existing PO files"
shopt -s nullglob
for PO in $LOCALES_DIR/*/LC_MESSAGES/gepetto.po; do
  echo "  - $PO"
  msgmerge --quiet --backup=off --update "$PO" "$POT_FILE"
done

echo "[i18n] Post-processing PO files (policy enforcement)"
if command -v python3 >/dev/null 2>&1; then
  python3 scripts/postprocess_po.py
else
  echo "Warning: python3 not found; skipping postprocess."
fi

echo "[i18n] Compiling MO files"
for PO in $LOCALES_DIR/*/LC_MESSAGES/gepetto.po; do
  MO="${PO%.po}.mo"
  msgfmt --output-file "$MO" "$PO"
done

echo "[i18n] Stripping obsolete (#~) entries from PO files"
for PO in $LOCALES_DIR/*/LC_MESSAGES/gepetto.po; do
  msgattrib --no-obsolete --output-file "$PO" "$PO"
done

echo "[i18n] Done. Updated: $POT_FILE and compiled .mo files."
