#!/usr/bin/env python3
"""
Post-process PO files according to project policy:

- Identify msgids that are new vs unchanged compared to POT at HEAD.
- For ALL locales keep unchanged translations; for new msgids, set msgstr 
  to the English source (msgid) to serve as a placeholder.
- Do NOT update PO-Revision-Date when only inserting English placeholders.
  Only update the date if we actually authored human translations (not done by
  this script). If a previous run updated the date, restore it from HEAD.

Assumptions: No msgctxt is used. Obsolete entries (#~) are left untouched.
"""
from __future__ import annotations
import os
import re
import subprocess
import sys
from datetime import datetime, timezone

RE_MSGID = re.compile(r'^msgid\s+"')
RE_MSGSTR = re.compile(r'^msgstr\s+"')
RE_OBSOLETE = re.compile(r'^#~\s')

def run(cmd: list[str]) -> str:
    return subprocess.check_output(cmd, text=True)

def parse_entries(text: str) -> list[dict]:
    # crude PO parser sufficient for msgid/msgstr editing
    lines = text.splitlines()
    entries = []
    i = 0
    n = len(lines)
    while i < n:
        # skip leading blank lines
        while i < n and lines[i].strip() == "":
            i += 1
        if i >= n:
            break
        start = i
        # consume until blank line separating entries
        while i < n and lines[i].strip() != "":
            i += 1
        entry_lines = lines[start:i]
        # detect obsolete
        if any(RE_OBSOLETE.match(l) for l in entry_lines):
            entries.append({
                'lines': entry_lines,
                'obsolete': True,
                'msgid': None,
                'msgstr': None,
                'msgid_span': None,
                'msgstr_span': None,
            })
            continue
        # find msgid and msgstr blocks
        def extract_block(prefix_re):
            s = None
            e = None
            val = []
            for idx, l in enumerate(entry_lines):
                if s is None:
                    if prefix_re.match(l):
                        s = idx
                        # first quoted part on same line
                        first = l.split('"', 1)[1]
                        first = first.rsplit('"', 1)[0]
                        val.append(first)
                else:
                    if l.startswith('"'):
                        part = l.strip()
                        if part.startswith('"') and part.endswith('"'):
                            val.append(part[1:-1])
                        else:
                            break
                    else:
                        e = idx
                        break
            if s is not None and e is None:
                e = len(entry_lines)
            return s, e, ''.join(val)
        mi_s, mi_e, mi = extract_block(RE_MSGID)
        ms_s, ms_e, ms = extract_block(RE_MSGSTR)
        entries.append({
            'lines': entry_lines,
            'obsolete': False,
            'msgid': mi,
            'msgstr': ms,
            'msgid_span': (mi_s, mi_e),
            'msgstr_span': (ms_s, ms_e),
        })
    return entries

def rebuild_entry(entry: dict, new_msgstr: str | None) -> list[str]:
    # Replace msgstr block content with new_msgstr; preserve other lines
    lines = entry['lines'][:]
    s, e = entry['msgstr_span']
    if s is None or new_msgstr is None:
        return lines
    # rebuild msgstr as single line (gettext will rewrap if needed)
    escaped = new_msgstr.replace('\\', '\\\\').replace('"', '\\"')
    lines[s:e] = [f'msgstr "{escaped}"']
    return lines

def get_msgids_from_pot(text: str) -> set[str]:
    return {e['msgid'] for e in parse_entries(text) if not e['obsolete'] and e['msgid'] is not None}

def get_map_from_po(text: str) -> dict[str,str]:
    out = {}
    for e in parse_entries(text):
        if e['obsolete'] or e['msgid'] is None:
            continue
        out[e['msgid']] = e['msgstr']
    return out

def get_header_revision_date(text: str) -> str | None:
    entries = parse_entries(text)
    if not entries:
        return None
    header = entries[0]
    s, e = header['msgstr_span']
    if s is None:
        return None
    lines = header['lines']
    for idx in range(s, e):
        line = lines[idx]
        if line.startswith('"PO-Revision-Date: '):
            # strip quotes and trailing \n"
            inner = line.strip()[1:-1]
            return inner.replace('PO-Revision-Date: ', '').rstrip('\n')
    return None

def set_header_revision_date(lines: list[str], new_date: str | None) -> list[str]:
    if not new_date:
        return lines
    out = lines[:]
    joined = "\n".join(out)
    entries = parse_entries(joined)
    if not entries:
        return out
    header = entries[0]
    s, e = header['msgstr_span']
    if s is None:
        return out
    replaced = False
    for idx in range(s, e):
        line = out[idx]
        if line.startswith('"PO-Revision-Date: '):
            out[idx] = f'"PO-Revision-Date: {new_date}\\n"'
            replaced = True
            break
    if not replaced:
        out.insert(e, f'"PO-Revision-Date: {new_date}\\n"')
    return out

def sanitize_po_revision_lines(text: str) -> str:
    # Collapse any accidental multiple \n escapes to a single one on the
    # PO-Revision-Date line within the header msgstr.
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if line.startswith('"PO-Revision-Date: '):
            # Replace multiple escaped newlines with a single one
            line = re.sub(r'(?:\\n){2,}\"$', r'\\n"', line)
            lines[i] = line
            break
    return "\n".join(lines) + ("\n" if text.endswith("\n") else "")

def main():
    repo_root = run(["git", "rev-parse", "--show-toplevel"]).strip()
    os.chdir(repo_root)
    pot_head = run(["git", "show", "HEAD:gepetto/locales/gepetto.pot"])  # baseline
    pot_cur = open("gepetto/locales/gepetto.pot", "r", encoding="utf-8").read()
    head_ids = get_msgids_from_pot(pot_head)
    cur_ids = get_msgids_from_pot(pot_cur)
    new_ids = cur_ids - head_ids
    unchanged_ids = cur_ids & head_ids

    locales_dir = "gepetto/locales"

    for loc in sorted(os.listdir(locales_dir)):
        loc_path = os.path.join(locales_dir, loc, "LC_MESSAGES", "gepetto.po")
        if not os.path.isfile(loc_path):
            continue
        cur_text = open(loc_path, "r", encoding="utf-8").read()
        cur_entries = parse_entries(cur_text)

        # Load HEAD translations for unchanged carry-over
        try:
            head_po = run(["git", "show", f"HEAD:{loc_path}"])
            head_map = get_map_from_po(head_po)
        except subprocess.CalledProcessError:
            head_map = {}

        changed = False
        inserted_english = False
        new_lines_all: list[str] = []
        for ent in cur_entries:
            if ent['obsolete'] or ent['msgid'] is None:
                new_lines_all.extend(ent['lines'])
                new_lines_all.append("")
                continue
            mid = ent['msgid']
            new_msgstr = ent['msgstr']
            if mid == "":
                # header; keep for now; we'll update date later if needed
                new_lines_all.extend(ent['lines'])
                new_lines_all.append("")
                continue
            if mid in unchanged_ids:
                # set to previous translation exactly if available
                if mid in head_map and head_map[mid] != new_msgstr:
                    new_msgstr = head_map[mid]
                    changed = True
            elif mid in new_ids:
                # Default to English source as placeholder for ALL locales
                if new_msgstr != mid:
                    new_msgstr = mid
                    changed = True
                    inserted_english = True
            # rebuild entry with possibly updated msgstr
            rebuilt = rebuild_entry(ent, new_msgstr)
            new_lines_all.extend(rebuilt)
            new_lines_all.append("")

        # If this run only inserted English placeholders, restore the
        # PO-Revision-Date from HEAD (do not claim human translation work)
        final_lines = new_lines_all
        # Always restore PO-Revision-Date from HEAD unless explicitly overridden
        try:
            head_po_text = run(["git", "show", f"HEAD:{loc_path}"])
            head_date = get_header_revision_date(head_po_text)
            final_lines = set_header_revision_date(final_lines, head_date)
        except subprocess.CalledProcessError:
            pass

        new_text = "\n".join(final_lines).rstrip() + "\n"
        new_text = sanitize_po_revision_lines(new_text)
        if new_text != cur_text:
            with open(loc_path, "w", encoding="utf-8") as f:
                f.write(new_text)
            print(f"Updated {loc_path} (changed={changed}, inserted_english={inserted_english})")
        else:
            print(f"No change for {loc_path}")

if __name__ == "__main__":
    sys.exit(main())
