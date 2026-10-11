# polinrider-reactime-analysis

Analysis and indicators for the **PolinRider** (DPRK-linked) compromise of
[`open-source-labs/Reactime`](https://github.com/open-source-labs/Reactime), including a
**previously-unreported Windows persistence component** that injects Electron applications
(VS Code and Discord) and re-resolves the command server on every launch.

Independent research by **Deep Woods Security**. Findings are from a controlled detonation
of the repository implant in an isolated lab on 2026-10-10. Samples are **not** hosted in
this repo (see `samples/`). No third-party victim data is included; all captured data
originates from a disposable analysis host.

---

## Summary

The `open-source-labs/Reactime` repository was compromised as part of the PolinRider
campaign: 20 of 22 branches carried a loader disguised as a web font, auto-executed by a
`.vscode/tasks.json` task configured with `runOn: folderOpen`. The `master`/`dev` branches
and the published npm package were clean.

This matches public PolinRider reporting on the delivery TTPs. What was observed here and is
**not** in the public reporting at the time of writing:

1. **Electron-application injection for persistence/reinfection.** The implant rewrites the
   JavaScript of locally installed Electron apps so they re-run the malware on every launch.
   The injected module self-labels as `app-vscode-eval` / `app-discord-eval`.
2. **A per-launch C2 re-resolution routine** inside that module, which independently resolves
   the command server from the Ethereum blockchain (NullReceiver technique) and reconnects.
3. **A custom string stream cipher** in the injected module (a golden-ratio-stepped PRNG over
   an encoded blob), distinct from the seeded character-shuffle documented for the loader.
4. **A command server at `193.247.144.38`** (nginx) using endpoints `POST /u/f` and
   `POST /u/e3`, and **serving its own Python 3.12.7 runtime** (a ~32 MB zip) to the victim
   rather than contacting python.org.

These are reported as observations, not as new techniques: Electron injection is itself a
known method, and the campaign (PolinRider) and blockchain dead-drop (NullReceiver) are
already named. See **Attribution and prior work**.

---

## Kill chain (Windows)

1. A developer opens the cloned repo in VS Code. A hidden `folderOpen` task runs
   `node` against the fake font (`fa-solid-900.woff2`), the stage-1 loader.
2. The loader resolves the C2 from the Ethereum blockchain (NullReceiver) and connects to
   `193.247.144.38` over socket.io, upgrading to a WebSocket.
3. It injects VS Code (`main.js` + dropped `main.inz.cjs`) and Discord
   (`discord_desktop_core/index.js`); an npm injection attempt failed (EPERM).
4. It downloads a private **Python 3.12.7** runtime served from the C2 and installs it.
5. The Python stage harvests data and exfiltrates it as encrypted multipart uploads to
   `POST /u/f` (fields: `client_id`, `path`, `sid`, file archive).

See [`IOCs.md`](IOCs.md) for the full indicator set, [`rules/`](rules/) for detection, and
[`analysis/`](analysis/) for the deobfuscated component and its string table.

---

## Attribution and prior work

Attribution to PolinRider / NullReceiver is consistent with public reporting, not an
independent determination. Primary references:

- Socket, *PolinRider: North Korea-Linked Supply Chain Campaign Expands* — https://socket.dev/blog/polinrider-north-korea-linked-supply-chain-campaign-expands
- OpenSourceMalware, *PolinRider dossier* — https://github.com/OpenSourceMalware/PolinRider
- The Hacker News, *Trojanized npm Packages Employ NullReceiver Tactic* — https://thehackernews.com/2026/08/trojanized-npm-packages-decode-c2-ip.html
- Sonatype, *Six npm Packages Use Ethereum Transactions to Retrieve Malicious Payloads* — https://www.sonatype.com/blog/six-npm-packages-use-ethereum-transactions-to-retrieve-malicious-payloads
- SOC Prime, *NullReceiver Hides C2 in Blank Ethereum Transfers* — https://socprime.com/active-threats/nullreceiver-advances-etherhiding-with-blank-crypto-transfers/
- Upstream advisory: `open-source-labs/Reactime` issue #368 — https://github.com/open-source-labs/Reactime/issues/368

## Disclosure

Reported to GitHub, CISA, and the FBI. Public advisory filed as Reactime issue #368.
