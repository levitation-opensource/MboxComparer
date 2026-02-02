# -*- coding: utf-8 -*-

#
# Author: Roland Pihlakas, 2026
#
# roland@simplify.ee
#
# Version 1.1.0
# 
# Roland Pihlakas licenses this file to you under the GNU Lesser General Public License, ver 2.1.
# See the LICENSE.txt file for more information.
#
# Repository: https://github.com/levitation-opensource/MboxComparer

"""
Streaming mbox-to-mbox comparator that:
- compares message-by-message in order (streaming - does not load whole mbox into memory)
- ignores the mbox "From " separator line (download date etc.)
- compares full content (headers + body) after canonicalisation
- optionally tolerates differences in blank-line runs "around MIME parts" (common after re-downloading the messages)
- reports Message-ID if present (or "From " separator as a fallback option) of differing messages

Default normalisation mode: "boundary_relaxed"
- preserves body formatting, except it normalises blank-line runs right around MIME boundary delimiter lines
- also normalises an initial run of blank lines at body start to a single blank line

Other modes:
- strict: exact compare (except "From " separator line and CRLF vs LF)
- relaxed: collapses ALL consecutive blank lines in body to a single blank line (more tolerant, less strict). Note: Corrupted messages are always processed in "relaxed" mode, unless "strict" mode is chosen.

Notes:
- Line endings are always canonicalised (CRLF/CR -> LF).

Usage:
  python mbox_comparer.py A.mbox B.mbox
  python mbox_comparer.py A.mbox B.mbox --mode strict
  python mbox_comparer.py A.mbox B.mbox --mode relaxed
  python mbox_comparer.py A.mbox B.mbox --max-mismatches 20
  python mbox_comparer.py A.mbox B.mbox --compare-corrupt-message-dates
  python mbox_comparer.py A.mbox B.mbox --hash-only-comparison
"""

from __future__ import annotations

import os
import argparse
import hashlib
import re
import traceback
from dataclasses import dataclass
from typing import BinaryIO, Optional, Tuple, Dict

from email.parser import BytesHeaderParser
from email.policy import default as default_policy

from progressbar import ProgressBar


# Heuristical regex for recognising mbox "From " separator lines, to reduce false positives.
# Typical example: From sender@example.com Sat Jan 27 12:34:56 2026
# TODO: should we match the email address part of the "From " separator as well?
_FROM_SEP_RE = re.compile(
    rb"^From\s+\S+\s+"
    rb"(Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+"
    rb"(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+"
    rb"\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4}\s*$"
)

def is_mbox_from_separator_line(line: bytes) -> bool:
    # Must start at column 0.
    if not line.startswith(b"From "):
        return False
    # Normalise line ending before regex match.
    line_without_eol = strip_eol(line)
    return bool(_FROM_SEP_RE.match(line_without_eol))


def strip_eol(line: bytes) -> bytes:
    # Convert CRLF/CR/LF to a logical line without any line ending.
    if line.endswith(b"\r\n"):
        return line[:-2]
    if line.endswith(b"\n") or line.endswith(b"\r"):
        return line[:-1]
    return line


def add_lf(line_wo_eol: bytes) -> bytes:
    return line_wo_eol + b"\n"


@dataclass
class MessageInfo:
    index: int
    sha256_hex: str
    size_canonical_bytes: int
    mbox_from_separator: str
    message_id: Optional[str]
    boundary: Optional[bytes]
    canonicalised_message: Optional[bytes]
    byteoffset: int   # TODO: Return exact byteoffset without buffering and print that offset in case mismatches are detected


class MboxStreamReader:
    """
    Reads an mbox file in a streaming manner and returns per-message digests
    after canonicalisation.
    """
    def __init__(self, path: str, mode: str, compare_corrupt_message_dates: bool):
        self.path = path
        self.mode = mode
        self.compare_corrupt_message_dates = compare_corrupt_message_dates
        self.f: BinaryIO = open(path, "rb", buffering=1024 * 1024)
        self._pending_mbox_from_separator: Optional[bytes] = None
        self._msg_index = 0

    def close(self) -> None:
        try:
            self.f.close()
        except Exception:
            pass

    def _read_until_next_separator(self) -> Optional[bytes]:
        """
        Find the next "From " separator line and return it.
        Stores it as _pending_mbox_from_separator if already read ahead.
        """
        if self._pending_mbox_from_separator is not None:
            mbox_from_separator = self._pending_mbox_from_separator
            self._pending_mbox_from_separator = None
            return mbox_from_separator

        for line in self.f:   # NB! BinaryIO iterates over lines NOT BYTES
            if is_mbox_from_separator_line(line):
                return line
        return None  # EOF

    def _is_corrupt_message(self, msg) -> bool:
        if self.compare_corrupt_message_dates:
            return False

        def try_get(name):
            try:
                return msg.get(name)
            except (IndexError, ValueError, AttributeError):   # handle "IndexError: list index out of range" and "ValueError: invalid arguments; address parts cannot contain CR or LF" and "AttributeError: 'str' object has no attribute 'token_type'"
                return ""  # TODO: is there a better way?

        result = (
            try_get("From") == "unknown sender <>"
            and try_get("Subject") == "Corrupt message received"
            and try_get("Message-ID") is None
        )
        return result

    def next_message(self, canonicalised_message_parts_separator: Optional[bytes] = None) -> Optional[MessageInfo]:

        mbox_from_separator = self._read_until_next_separator()
        if mbox_from_separator is None:
            return None

        self._msg_index += 1
        idx = self._msg_index

        canonicalised_message_parts = [] if canonicalised_message_parts_separator is not None else None
        h = hashlib.sha256()
        size = 0

        # Read headers (raw bytes, up to blank line)
        header_lines = []
        while True:
            line = self.f.readline()
            if not line:
                # EOF mid-message: treat as message end
                break
            if is_mbox_from_separator_line(line):
                # Unexpected separator inside headers: push back and treat as end
                self._pending_mbox_from_separator = line
                break

            line_without_eol = strip_eol(line)
            header_lines.append(line_without_eol)

            if len(line_without_eol) == 0:
                # End of headers (blank line)
                break

        # If we ended because EOF without a blank line, headers may be incomplete;
        # still hash what we have, in canonical form, and continue (body empty).
        # Parse headers to extract Message-ID and boundary.
        raw_header_block = b"\n".join(header_lines) + b"\n"
        parser = BytesHeaderParser(policy=default_policy)
        msg = parser.parsebytes(raw_header_block)

        message_id = msg.get("Message-ID")
        if message_id is not None:
            message_id = str(message_id).strip()

        is_corrupt_message = self._is_corrupt_message(msg)   # In case of corrupt messages, the mbox contains the message download date, not sending date

        boundary = None
        boundaries = set()
        ctype = msg.get_content_type()
        # Only meaningful for multipart
        if ctype and ctype.lower().startswith("multipart/"):
            b = msg.get_boundary()
            if b:
                # Store as bytes for fast boundary-line detection
                boundary = b.encode("utf-8", "surrogateescape")
                boundaries.add(boundary)

        # Hash headers in canonical LF form
        # (We already collected without EOL; now write each with LF.)
        # Important: preserve header lines exactly (apart from CRLF -> LF).
        for header_line in header_lines:
            if is_corrupt_message and header_line.strip().lower().startswith(b"date:"):
                continue
            line_out = add_lf(header_line)
            if canonicalised_message_parts is not None:
                canonicalised_message_parts.append(line_out)
            h.update(line_out)
            size += len(line_out)

        # If headers ended without a blank line (no separator), we did not include one;
        # but in canonical mbox messages there is usually a blank line. We only hash what exists.

        # If we already hit a separator during headers, body is empty.
        if self._pending_mbox_from_separator is not None:
            return MessageInfo(
                index=idx,
                sha256_hex=h.hexdigest(),
                size_canonical_bytes=size,
                mbox_from_separator=mbox_from_separator.strip(),
                message_id=message_id,
                boundary=boundary,
                canonicalised_message=canonicalised_message_parts_separator.join(canonicalised_message_parts) if canonicalised_message_parts_separator is not None else None,
                byteoffset=self.f.tell(),
            )

        # --- Read body until next separator ---
        # Canonicalisation rules:
        # - CRLF/CR -> LF
        # - strict: hash body lines exactly (LF-normalised), including blank lines
        # - relaxed: collapse runs of blank lines in body to a single blank line
        # - boundary_relaxed: only normalise blank runs adjacent to MIME boundary lines,
        #   plus normalise initial body-leading blank run.
        num_pending_blanks = 0
        prev_was_boundary = False
        at_body_start = True
        at_multipart_header = boundary is not None   # Handle linebreaks after "This is a multi-part message in MIME format" line as lineabreaks before body start
        at_base64_part = False


        def flush_blanks(force_collapse_to_one: bool) -> None:
            nonlocal num_pending_blanks, size, at_body_start, canonicalised_message_parts
            if num_pending_blanks <= 0:
                return
            if force_collapse_to_one:
                line_out = b"\n"
                if canonicalised_message_parts is not None:
                    canonicalised_message_parts.append(line_out)
                h.update(line_out)
                size += 1
            else:
                line_out = b"\n" * num_pending_blanks
                if canonicalised_message_parts is not None:
                    canonicalised_message_parts.append(line_out)
                h.update(line_out)
                size += num_pending_blanks
            num_pending_blanks = 0
            at_body_start = False

        def is_boundary_line(line_without_eol: bytes) -> bool:
            if not boundaries:
                return False
            # Boundary delimiter lines are: --<boundary> or --<boundary>--
            # (optionally with trailing whitespace)
            if not line_without_eol.startswith(b"--"):
                return False
            core = line_without_eol.strip()
            for boundary in boundaries:
                if boundary and core == b"--" + boundary:
                    return True
                if boundary and core == b"--" + boundary + b"--":
                    return True
            return False

        def is_next_boundary(line_without_eol: bytes) -> Optional[bytes]:
            attribute1 = b"boundary=\""
            attribute2 = b"boundary="   # Boundary without quotes
            parts = line_without_eol.split(b";")   # NB! Need to always split by ; since sometimes the attribute ends with 'boundary="abc";'
            for part in parts:
                core = part.strip()  # Sometimes the line starts with a tab, also there are spaces or tabs after ;
                core_lower = core.lower()
                if core_lower.startswith(attribute1):
                    return core[len(attribute1) : -1]
                elif core_lower.startswith(attribute2):
                    return core[len(attribute2) : ]

            return None

        #/ def is_next_boundary(s: bytes) -> Optional[bytes]:
                

        while True:
            line = self.f.readline()
            if not line:
                # EOF: End message
                break

            if is_mbox_from_separator_line(line):
                self._pending_mbox_from_separator = line
                break

            line_without_eol = strip_eol(line)  # Line without EOL

            if self.mode == "strict":
                line_out = add_lf(line_without_eol)
                if canonicalised_message_parts is not None:
                    canonicalised_message_parts.append(line_out)
                h.update(line_out)
                size += len(line_out)
                continue

            # "relaxed" / "boundary_relaxed" mode:
            if len(line_without_eol) == 0:
                num_pending_blanks += 1
                continue

            this_is_boundary = is_boundary_line(line_without_eol)
            if this_is_boundary:
                if at_base64_part:
                    num_pending_blanks += 1
                at_base64_part = False
            elif prev_was_boundary:
                next_boundary = is_next_boundary(line_without_eol)
                if next_boundary:
                    boundaries.add(next_boundary)     # NB! Preserve ALL earlier boundaries too, as THEY are also sometimes reused later
                else:
                    core_lower = line_without_eol.strip().lower()
                    if core_lower == b"content-transfer-encoding: base64":
                        at_base64_part = True
                    elif core_lower == b"":     # Line containing blanks after boundary
                        num_pending_blanks += 1
                        continue

            # "relaxed" / "boundary_relaxed" mode:
            if at_multipart_header and num_pending_blanks > 0:  # Handle linebreaks after "This is a multi-part message in MIME format" line as lineabreaks before body start
                num_pending_blanks = 0
                at_body_start = False
            elif at_body_start and num_pending_blanks > 0:
                # Normalise leading blank run at body start.
                flush_blanks(force_collapse_to_one=True)

            if this_is_boundary:
                # If we have blanks before a boundary: normalise to a no blank lines, because sometimes there are no blank lines in that place
                if num_pending_blanks > 0:
                    num_pending_blanks = 0  # Ignore blanks before boundary
                line_out = add_lf(line_without_eol)
                if canonicalised_message_parts is not None:
                    canonicalised_message_parts.append(line_out)
                h.update(line_out)
                size += len(line_out)
                prev_was_boundary = True
                at_body_start = False
                at_multipart_header = False
                continue

            # Non-blank, non-boundary line:
            if num_pending_blanks > 0:
                # If blanks are right after a boundary, normalise them.
                if prev_was_boundary:
                    flush_blanks(force_collapse_to_one=True)
                elif at_base64_part:
                    num_pending_blanks = 0  # ignore newlines inside base64 encoded part
                elif is_corrupt_message:  # NB! For corrupt messages, always collapse the newlines inside the body since the body will contain the original message headers as well. Unfortunately, it would be too complicated to separate the body of the original message from the headers of the original message. Corrupt messages are usually spam, so it is not so urgent anyway.
                    flush_blanks(force_collapse_to_one=True)  # Collapse ALL blank runs to one, including the ones inside the message body
                elif self.mode == "relaxed":
                    flush_blanks(force_collapse_to_one=True)  # Collapse ALL blank runs to one, including the ones inside the message body
                else:
                    # Preserve blanks elsewhere.
                    flush_blanks(force_collapse_to_one=False)
                prev_was_boundary = False

            if at_base64_part:
                line_out = line_without_eol  # Ignore newlines inside base64 encoded part
            else:
                line_out = add_lf(line_without_eol)
            if canonicalised_message_parts is not None:
                canonicalised_message_parts.append(line_out)
            h.update(line_out)
            size += len(line_out)
            at_body_start = False

        # Flush trailing blanks at end of message
        if self.mode == "relaxed":
            flush_blanks(force_collapse_to_one=True)
        elif self.mode == "boundary_relaxed":
            if at_body_start and num_pending_blanks > 0:
                flush_blanks(force_collapse_to_one=True)
            elif prev_was_boundary and num_pending_blanks > 0:
                flush_blanks(force_collapse_to_one=True)
            else:
                flush_blanks(force_collapse_to_one=False)

        return MessageInfo(
            index=idx,
            sha256_hex=h.hexdigest(),
            size_canonical_bytes=size,
            mbox_from_separator=mbox_from_separator.strip(),
            message_id=message_id,
            boundary=boundary,
            canonicalised_message=canonicalised_message_parts_separator.join(canonicalised_message_parts) if canonicalised_message_parts_separator is not None else None,
            byteoffset=self.f.tell(),
        )

    #/ def next_message(self, canonicalised_message_parts_separator: bytes = b"") -> Optional[MessageInfo]:

#/ class MboxStreamReader:


def compare_mboxes(path_a: str, path_b: str, mode: str, max_mismatches: int, compare_corrupt_message_dates: bool, hash_only_comparison: bool) -> int:

    ra = MboxStreamReader(path_a, mode, compare_corrupt_message_dates)
    rb = MboxStreamReader(path_b, mode, compare_corrupt_message_dates)
    mismatches = 0
    compared = 0

    try:
        size_a = os.path.getsize(path_a)
        size_b = os.path.getsize(path_b)
        totalsize = size_a + size_b

        ma_byteoffset = 0
        mb_byteoffset = 0
        prev_ma_message_id = None
        prev_mb_message_id = None
        prev_ma_mbox_from_separator = b""
        prev_mb_mbox_from_separator = b""
        error = False

        # NB! Need to begin all print statements with a space or empty line to mitigate the progressbar having cursor located at one space before the end of the previous line.
        with ProgressBar(max_value=totalsize, granularity=1000 * 1000) as bar:
            while True:                
                try:
                    ma = ra.next_message(canonicalised_message_parts_separator=None if hash_only_comparison else b"")
                    mb = rb.next_message(canonicalised_message_parts_separator=None if hash_only_comparison else b"")

                    if ma is None and mb is None:
                        break

                    if ma:
                        ma_byteoffset = ma.byteoffset
                    if mb:
                        mb_byteoffset = mb.byteoffset
                    byteoffset = ma_byteoffset + mb_byteoffset
                    bar.update(byteoffset // (1000 * 1000) * (1000 * 1000))

                    prev_ma_message_id = ma.message_id
                    prev_mb_message_id = mb.message_id
                    prev_ma_mbox_from_separator = ma.mbox_from_separator
                    prev_mb_mbox_from_separator = mb.mbox_from_separator

                    if ma is None or mb is None:
                        # Different number of messages
                        mismatches += 1
                        if ma is None:
                            print()
                            print(f"Mismatch: {path_a} ended early; {path_b} has extra messages (next index {mb.index}).")
                        else:
                            print()
                            print(f"Mismatch: {path_b} ended early; {path_a} has extra messages (next index {ma.index}).")
                        if mismatches >= max_mismatches:
                            break
                        continue

                    compared += 1

                    if ma.sha256_hex != mb.sha256_hex or (not hash_only_comparison and ma.canonicalised_message != mb.canonicalised_message):
                        mismatches += 1

                        if ma.message_id:
                            msgid_a = ma.message_id 
                        else:
                            msgid_a = b"from line: " + ma.mbox_from_separator

                        if mb.message_id:
                            msgid_b = mb.message_id
                        else:
                            msgid_b = b"from line: " + mb.mbox_from_separator

                        print()
                        print(
                            f"Mismatch at message #{ma.index}:\n"
                            f"  A: sha256={ma.sha256_hex}  canonical_bytes={ma.size_canonical_bytes}  Message-ID={msgid_a}\n"
                            f"  B: sha256={mb.sha256_hex}  canonical_bytes={mb.size_canonical_bytes}  Message-ID={msgid_b}\n"
                        )
                        if mismatches >= max_mismatches:
                            break

                        if compared % 1000 == 0:
                            print(f"Messages compared: {compared}")   # NB! Note that here we do not add space before the words

                    elif compared % 1000 == 0:
                        print(f" Messages compared: {compared}")  # NB! Note the space before the words

                except Exception as ex:
                    msg = str(ex) + os.linesep + traceback.format_exc()
                    print()
                    print(msg)
                    print()

                    if prev_ma_message_id:
                        msgid_a = prev_ma_message_id 
                    else:
                        msgid_a = b"from line: " + prev_ma_mbox_from_separator

                    if prev_mb_message_id:
                        msgid_b = prev_mb_message_id
                    else:
                        msgid_b = b"from line: " + prev_mb_mbox_from_separator

                    print(
                        f"Exception at message #{ma.index}\n"
                        f"Last successfully processed messages were:\n"
                        f"  A: sha256={ma.sha256_hex}  canonical_bytes={ma.size_canonical_bytes}  Message-ID={msgid_a}\n"
                        f"  B: sha256={mb.sha256_hex}  canonical_bytes={mb.size_canonical_bytes}  Message-ID={msgid_b}\n"
                    )

                    print()
                    print("Cannot recover from the exception, stopping...")
                    break

            #/ while True: 

            if mismatches < max_mismatches:
                bar.update(totalsize)   # Remove the byteoffset rounding so that progress jumps to full 100%

        #/ with ProgressBar(max_value=totalsize, granularity=1000 * 1000) as bar:

        print()
        print(f"Compared {compared} message pairs. Mismatches: {mismatches}. Mode: {mode}.")
        return 0 if mismatches == 0 else 2

    finally:
        ra.close()
        rb.close()

#/ def compare_mboxes(path_a: str, path_b: str, mode: str, max_mismatches: int, compare_corrupt_message_dates: bool) -> int:


def main() -> None:

    ap = argparse.ArgumentParser(description="Streaming comparator for two mbox files.")

    ap.add_argument("mbox_a", help="First mbox file")
    ap.add_argument("mbox_b", help="Second mbox file")

    ap.add_argument(
        "--mode",
        choices=["strict", "boundary_relaxed", "relaxed"],
        default="boundary_relaxed",
        help="Normalisation mode (default: boundary_relaxed)",
    )

    ap.add_argument(
        "--max-mismatches",
        type=int,
        default=1,
        help="Stop after this many mismatches (default: 1)",
    )

    ap.add_argument(
        "--compare-corrupt-message-dates",
        action="store_true",
        default=False,
        help="Compares dates of corrupt messages (default: off). Default is off because Date header field of these messages contains download date, not send date.",
    )

    ap.add_argument(
        "--hash-only-comparison",
        action="store_true",
        default=False,
        help="Compares messages only via hashes to provide minor speed boost (default: off). Default is off (i.e comparison of canonicalised messages byte by byte is on) because that avoids the theoretical risk of hash collisions at a minor speed cost (about 5%).",
    )

    args = ap.parse_args()

    compare_mboxes(args.mbox_a, args.mbox_b, args.mode, args.max_mismatches, args.compare_corrupt_message_dates, args.hash_only_comparison)

    quit()

#/ def main() -> None:


if __name__ == "__main__":
    main()
