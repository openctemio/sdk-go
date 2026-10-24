### Changed: tool.yaml errors say how to fix them

- An unknown capability names the nearest taxonomy ids (`did you mean scan.ports@1?`), or the majors that exist when only the major is wrong.
- An unknown CTIS asset or finding type is quoted, with the nearest type and, for finding types, the allowed set; common words (`url`, `ip`, `port`, `repo`, `image`) map to the CTIS type.
- An unknown key is reported at its JSON pointer with the nearest known key, or where it belongs (`/timeout: unknown key; did you mean /resources/timeout?`).
- A value of the wrong type says what it must be in plain words (`/version: must be a string; quote it ("1.0.0")`), never a Go type name.
- Only the wording changed: nothing newly accepted or refused. Echoed input is quoted and cut to 64 bytes.
