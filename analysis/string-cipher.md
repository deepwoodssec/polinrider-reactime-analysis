# String obfuscation in `main.inz.cjs`

The injected VS Code backdoor module hides all of its strings (endpoint paths, RPC
URLs, event names, labels) inside a single encoded blob. Each string is recovered at
runtime by one decoder function. This note documents that decoder so the recovery is
reproducible and the deobfuscated output in this directory can be independently checked.

## The decoder

```js
function decode(seed, base, len) {
  var out = "";
  for (var i = 0; i < len; i++) {
    seed = seed + 2654435769 | 0;                 // step the PRNG
    var k = ((seed ^ seed >>> 13) % 95 + 95) % 95; // keystream byte, 0..94
    var c = BLOB.charCodeAt(base + i) - 32;         // encoded char, 0..94
    var p = ((c - k) % 95 + 95) % 95;               // plaintext char, 0..94
    out += String.fromCharCode(p + 32);             // back to printable ASCII
  }
  return out;
}
```

(In the shipped sample the function is named `tFUgC5`, the blob is a global named
`q5gtkF`, and the three arguments are a per-string seed, an offset into the blob, and a
length. Names are arbitrary and change between builds; the math does not.)

## How it works

It is a stream cipher over the 95 printable ASCII characters (0x20 to 0x7E).

- **Keystream.** A linear congruential generator steps by the constant `2654435769`
  (`0x9E3779B9`, the 32-bit golden-ratio constant used widely as a hash/PRNG multiplier
  and in xxHash/Fibonacci hashing). `| 0` forces 32-bit signed wraparound. Each step is
  mixed with an xorshift (`seed ^ seed >>> 13`) and reduced mod 95 to yield one keystream
  value in `0..94`.
- **Combination.** Plaintext and ciphertext are mapped into `0..94` by subtracting 32.
  Encoding adds the keystream mod 95; decoding subtracts it. The doubled
  `(x % 95 + 95) % 95` is just a positive modulo.
- **Per-string seed.** Each call passes its own starting `seed`, so every string gets an
  independent keystream. There is no key exchange and no secret beyond the constant and
  the blob; the sample carries everything needed to decrypt itself.

## Reproducing the recovered strings

The recovered string table is in
[`main.inz.cjs.decoded-strings.txt`](main.inz.cjs.decoded-strings.txt); the fully
deobfuscated module (control flow unflattened by `webcrack`, strings inlined) is in
[`main.inz.cjs.deobfuscated.js`](main.inz.cjs.deobfuscated.js).

To reproduce independently: run the sample under a Node harness that replaces the decoder
with a logging wrapper and stubs `eval`, `Function`, `vm`, `child_process`, network, and
`fs` writes, so the strings resolve without the payload executing. Every call to the
decoder then prints its `(seed, base, len)` and the plaintext it returns. This is how the
table in this directory was produced; do it only in a disposable VM.

## Relation to the stage-1 loader

This is **not** the same obfuscation as the stage-1 font loader. The loader uses a seeded
character-shuffle; this module uses the golden-ratio stream cipher above. Treat them as
two distinct obfuscation schemes within the same campaign.
