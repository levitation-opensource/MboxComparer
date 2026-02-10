# Mbox file comparer with efficient memory usage

Mbox-to-mbox comparator for data integrity verification. It compares full content of emails (headers and body) after canonicalisation, and optionally tolerates differences in the lengths of blank-line runs.

- Does not load whole mbox into memory by using streaming and hashing.
- Ignores the mbox "From " separator line (download date etc).
- Compares full content (headers + body) after canonicalisation.
- Optionally tolerates differences in blank-line runs "around MIME parts" (common after re-downloading the messages).
- Reports Message-ID if present (or "From " separator as a fallback option) of differing messages.

## Comparison modes

### Normalisation modes

**Default normalisation mode: `boundary_relaxed`**
- Preserves body formatting, except it normalises blank-line runs right around MIME boundary delimiter lines.
- Also normalises an initial run of blank lines at body start to a single blank line.

**Other normalisation modes:**
- `strict`: Exact comparison of messages (except "From " separator line and CRLF vs LF differences).
- `relaxed`: Collapses ALL consecutive blank lines in body to a single blank line (more tolerant, less strict)

**Notes:**
- Line endings are always canonicalised (CRLF/CR -> LF).

### Mbox message order handling

- By default, it assumes messages are in the same order.
- `--order-tolerant-comparison` - Ignores message order differences between the mboxes (default: off). **Strongly recommended to enable only together with `--hash-only-comparison`**, else this order tolerant comparison mode would most likely consume huge amount of memory.
- When both `--order-tolerant-comparison --hash-only-comparison` are specified then uses relatively little memory even when message orderings differ between mboxes.

### Other parameters:

- `--max-mismatches [number]` - Stop after this many mismatches (default: 1).
- `--compare-corrupt-message-dates` - Compares dates of corrupt messages (default: off). Default is off because Date header field of these messages contains download date, not send date.
- `--hash-only-comparison` - Compares messages only via hashes to provide minor speed boost (default: off). Default is off (i.e comparison of canonicalised messages byte by byte is on) because that avoids the theoretical risk of hash collisions at a minor speed cost (about 5%).


## Usage

Some examples (in practice, the parameters can be combined):
```
python mbox_comparer.py A.mbox B.mbox
python mbox_comparer.py A.mbox B.mbox --mode strict
python mbox_comparer.py A.mbox B.mbox --mode relaxed
python mbox_comparer.py A.mbox B.mbox --max-mismatches 20
python mbox_comparer.py A.mbox B.mbox --compare-corrupt-message-dates
python mbox_comparer.py A.mbox B.mbox --order-tolerant-comparison --hash-only-comparison
python mbox_comparer.py A.mbox B.mbox --order-tolerant-comparison
```


## Current project state

Ready to use. Maintained and in active use.
