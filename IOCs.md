# Indicators of Compromise

PolinRider / NullReceiver compromise of `open-source-labs/Reactime`. Windows variant,
captured 2026-10-10. IPs are live; defang before pasting into tools you don't control.

## Command and control

| Type | Value |
|---|---|
| C2 | `193.247.144.38` (nginx/1.31.4), TCP 80 and 443 |
| Related C2 (per Socket) | `166.88.73.46`, `166.88.134.62`, `23.27.13.135` |
| Endpoints | `POST /u/f`, `POST /u/e3`, `POST /verify-human/A9-0476-3`, `POST /snv`, `GET /socket.io/?EIO=4` (upgrades to WebSocket) |
| Request header | `Sec-V: A9-0476-3` |
| Exfil User-Agent | `python-requests/2.32.3` |
| socket.io VERSION | `260902` |

### Exfil format (`POST /u/f`)
`multipart/form-data` with fields: `client_id` (`<host>$<user>`), `path` (`_auto`),
`sid` (Windows machine SID), and a file archive (encrypted; ~2.8 MB observed).

## Blockchain C2 resolution (NullReceiver)

| Type | Value |
|---|---|
| Dead-drop wallet | `0xa322E5f3D311D3080e6f0121063e9aDC2490Ef1a` |
| Method | `eth_blockNumber`, `eth_getBlockByNumber(n, true)`; decode C2 IP from a transaction's destination field |
| RPC resolvers | `https://1rpc.io/eth`, `https://eth.drpc.org`, `https://ethereum.publicnode.com`, `https://eth-mainnet.public.blastapi.io`, `https://eth.blockscout.com/api`, `https://cloudflare-eth.com`, `https://rpc.ankr.com/eth` |

RPC providers are legitimate shared infrastructure, context, not blocklist candidates.

## Markers / tags

| Marker | Where |
|---|---|
| `9-0476-3` | stage-1 loader |
| `A9-0476-3` | stage-2 / build + victim tag |
| `RS260605` | injected module header |
| `M260630A` | injection site comment (VS Code + Discord) |
| `app-vscode-eval` | VS Code injected module label |
| `app-discord-eval` | Discord injected module label |
| `__inzV`, `__inzCR` | VS Code `main.js` injection identifiers |

## Host artifacts (Windows)

- VS Code `...\resources\app\out\main.js` modified; first line prepended:
  ```js
  import{createRequire as __inzCR}from'module';const __inzV="A9-0476-3";__inzCR(import.meta.url)("./main.inz.cjs");/*M260630A*/
  ```
- Dropped: `...\resources\app\out\main.inz.cjs`
- Discord `...\discord_desktop_core\index.js` modified (backdoor appended after whitespace padding, labeled `app-discord-eval /*M260630A*/`)
- Attempted (failed, EPERM): `C:\Program Files\nodejs\node_modules\npm\lib\cli.js`
- C2-served Python 3.12.7 runtime (served as `application/zip`, ~32 MB)

## File hashes (SHA-256)

See [`SHA256SUMS.txt`](SHA256SUMS.txt). Samples are available on MalwareBazaar by hash
(see [`samples/README.md`](samples/README.md)); they are not stored in this repo.

| File | SHA-256 |
|---|---|
| `fa-solid-900.woff2` (stage-1 loader) | `2bbdcf9ae37d5c5e320a328fcd8402afe474394f433136e39cc133c9686ca9ed` |
| `babel.config.js` (loader variant) | `afdad16c539409d089961c23f8dc2b8df2b01789f4b4657cf4bbfc046622f307` |
| `main.inz.cjs` (VS Code backdoor) | `42ff8df9907110ef87aa15876215f77a3862c42f94d71070a0f16ee1b7a7d223` |
| `index.js` (trojanized Discord core) | `569798ae1b2b3f07a27a6f328bbb8238b23171669b369412c33ff7625def9c7f` |
| `main.js` (modified VS Code entry) | `78f645a6a557327e67810b3568ef12e5aad61ac6aac7c81514e133d34600b978` |

Loader git blob (identical across infected branches): `f68e0443b0b607be5042b5d24dd425a1a0692769`
