#!/usr/bin/env python3
"""Compile first-party INI catalogs into checked keys and embedded defaults."""
import argparse
import configparser
import json
from pathlib import Path
import re

SECTIONS = {"strings", "formats", "labels"}
INTEGER_MACRO = re.compile(r"@(?:PRI[diouxX](?:8|16|32|64|PTR|MAX))@")

PRINTF_SPECIFIER = re.compile(
    r"%(?:[1-9][0-9]*\$)?[-+ #0']*(?:[0-9]+|\*(?:[1-9][0-9]*\$)?)?"
    r"(?:\.(?:[0-9]*|\*(?:[1-9][0-9]*\$)?))?(?:hh|ll|[hljztL])?[diouxXfFeEgGaAcsp]"
)


def check_format(value: str, path: Path, key: str) -> None:
    pattern = INTEGER_MACRO.sub(lambda match: "l" + match.group()[4], value)
    offset = 0
    while offset < len(pattern):
        if pattern[offset] != "%":
            offset += 1
        elif pattern.startswith("%%", offset):
            offset += 2
        else:
            match = PRINTF_SPECIFIER.match(pattern, offset)
            if match is None:
                raise ValueError(f"{path}: invalid printf format in {key} at {offset}")
            offset = match.end()

def cpp_string(value: str) -> str:
    chunks = []
    position = 0
    for match in INTEGER_MACRO.finditer(value):
        chunks.append(cpp_bytes(value[position:match.start()]))
        chunks.append(match.group()[1:-1])
        position = match.end()
    chunks.append(cpp_bytes(value[position:]))
    return " ".join(chunks)


def cpp_bytes(value: str) -> str:
    escaped = []
    for byte in value.encode("utf-8"):
        if byte in (34, 92):
            escaped.append("\\" + chr(byte))
        elif 32 <= byte < 127:
            escaped.append(chr(byte))
        else:
            escaped.append(f"\\{byte:03o}")
    return '"' + "".join(escaped) + '"'


def write_changed(path: Path, content: str) -> None:
    if not path.exists() or path.read_text() != content:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_text(content)
        temporary.replace(path)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("catalogs", nargs="+", type=Path)
    args = parser.parse_args()
    entries = {}
    for path in sorted(args.catalogs):
        catalog = configparser.ConfigParser(interpolation=None, delimiters=("=",),
                                           empty_lines_in_values=False)
        catalog.optionxform = str
        with path.open(encoding="utf-8-sig") as stream:
            catalog.read_file(stream)
        if catalog.defaults():
            raise ValueError(f"{path}: DEFAULT entries are not supported")
        for section in catalog.sections():
            if section not in SECTIONS:
                raise ValueError(f"{path}: unknown section {section}")
            for key, raw in catalog.items(section):
                if not re.fullmatch(r"[A-Z][A-Za-z0-9_]*", key) or key == "Count":
                    raise ValueError(f"{path}: invalid descriptive key {key}")
                if key in entries:
                    raise ValueError(f"{path}: duplicate key {key}")
                value = json.loads(raw)
                if not isinstance(value, str):
                    raise ValueError(f"{path}: {key} must be a quoted string")
                value.encode("utf-8")  # Reject lone surrogate escapes.
                if "@PRI" in INTEGER_MACRO.sub("", value):
                    raise ValueError(f"{path}: invalid integer-format token in {key}")
                if section == "labels" and ("##" in value or "\0" in value):
                    raise ValueError(f"{path}: {key} contains a hidden label ID or null")
                if section == "formats":
                    if "\0" in value:
                        raise ValueError(f"{path}: null in printf format {key}")
                    check_format(value, path, key)
                entries[key] = (value, section)
    keys = sorted(entries)
    header = "#pragma once\n#include <cstddef>\nnamespace l10n {\nenum class Key : std::size_t {\n"
    header += "".join(f"  {key},\n" for key in keys)
    header += "  Count\n};\n}\n"
    data = '#pragma once\n#include "LocalizationKeys.h"\n#include <array>\n#include <cinttypes>\n#include <string_view>\nnamespace l10n::generated {\nusing namespace std::literals;\n'
    data += "struct Entry { std::string_view name; std::string_view english; bool format; bool label; };\n"
    data += f"inline constexpr std::array<Entry, {len(keys)}> entries{{{{\n"
    for key in keys:
        value, section = entries[key]
        data += f"  {{{cpp_bytes(key)}, {cpp_string(value)}sv, {str(section == 'formats').lower()}, {str(section == 'labels').lower()}}},\n"
    data += "}};\n"
    windows = [key for key in keys if key.startswith("Window") and entries[key][1] == "labels"]
    data += f"inline constexpr std::array<Key, {len(windows)}> windows{{{{\n"
    data += "".join(f"  Key::{key},\n" for key in windows)
    data += "}};\n}\n"
    write_changed(args.output_dir / "LocalizationKeys.h", header)
    write_changed(args.output_dir / "LocalizationData.h", data)


if __name__ == "__main__":
    main()
