# Samples

Live malware is **not** stored in this repository. This directory lists the samples by
hash so they can be matched, retrieved, and verified without this repo redistributing
executable code.

All five samples were submitted to **VirusTotal** on 2026-10-11 and can be looked up by
SHA-256 at `https://www.virustotal.com/gui/file/<sha256>`. As of first submission every
one read **0 detections**, which is expected: the strings are hidden behind a custom
stream cipher (see [`../analysis/string-cipher.md`](../analysis/string-cipher.md)) and the
two host files are mostly legitimate application code. Match against your own telemetry
with the rules in [`../rules/`](../rules/) rather than relying on signature AV. Full
SHA-256 list: [`../SHA256SUMS.txt`](../SHA256SUMS.txt).

| File | SHA-256 | Role |
|---|---|---|
| `fa-solid-900.woff2` | `2bbdcf9ae37d5c5e320a328fcd8402afe474394f433136e39cc133c9686ca9ed` | Stage-1 loader disguised as a web font (37,717 bytes) |
| `babel.config.js` | `afdad16c539409d089961c23f8dc2b8df2b01789f4b4657cf4bbfc046622f307` | Build-time variant of the loader (37,856 bytes, CRLF) |
| `main.inz.cjs` | `42ff8df9907110ef87aa15876215f77a3862c42f94d71070a0f16ee1b7a7d223` | VS Code Electron-injection backdoor module |
| `main.js` | `78f645a6a557327e67810b3568ef12e5aad61ac6aac7c81514e133d34600b978` | VS Code entry point after injection |
| `index.js` | `569798ae1b2b3f07a27a6f328bbb8238b23171669b369412c33ff7625def9c7f` | Trojanized Discord `discord_desktop_core` |

### Additional hashes for the stage-1 loader

For matching against systems that index MD5 / SHA-1 or git objects:

- `fa-solid-900.woff2` — MD5 `dac8b16b03fbb22d774afbd891cb15a6`, SHA-1 `844d41fb8883b80f03700ec0440e989934b30899`
- `babel.config.js` — MD5 `0c29a9faf391c543ebd043a24d96fdf8`, SHA-1 `06432fce5ae7519022a711f11b9b848722be2fc3`
- Loader git blob (identical on all 20 infected branches): `f68e0443b0b607be5042b5d24dd425a1a0692769`

The deobfuscated backdoor source and its recovered string table are in
[`../analysis/`](../analysis/) — those are analysis artifacts, not runnable malware.
