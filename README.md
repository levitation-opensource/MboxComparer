# Streaming mbox-to-mbox comparator

- Compares message-by-message in order (streaming - does not load whole mbox into memory).
- Ignores the mbox "From " separator line (download date etc).
- Compares full content (headers + body) after canonicalisation.
- Optionally tolerates differences in blank-line runs "around MIME parts" (common after re-downloading the messages).
- Reports Message-ID if present (or "From " separator as a fallback option) of differing messages.


## Comparison modes

Default normalisation mode: `boundary_relaxed`
- Preserves body formatting, except it normalises blank-line runs right around MIME boundary delimiter lines.
- Also normalises an initial run of blank lines at body start to a single blank line.

**Other modes:**
- `strict`: Exact comparison of messages (except "From " separator line and CRLF vs LF differences).
- `relaxed`: Collapses ALL consecutive blank lines in body to a single blank line (more tolerant, less strict)

**Notes:**
- Line endings are always canonicalised (CRLF/CR -> LF).


## Usage

  python compare_mbox.py A.mbox B.mbox
  python compare_mbox.py A.mbox B.mbox --mode strict
  python compare_mbox.py A.mbox B.mbox --mode relaxed
  python compare_mbox.py A.mbox B.mbox --max-mismatches 20
  python compare_mbox.py A.mbox B.mbox --compare-corrupt-message-dates


## Current project state

Ready to use. Maintained and in active use.
