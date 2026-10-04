// BOLT-11 invoice decoder. Follows the reader rules in lightning/bolts 11-payment-encoding.md:
// it fails on a bad checksum, mixed case, an unknown multiplier, sub-millisatoshi amounts, a
// missing payment secret, an unrecoverable signature, and a high-S signature when the payee
// key is stated. Fields with the wrong length are skipped, as the spec requires.
import * as S from './secp256k1.js';

const CH = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
const polymod = (v) => {
  let c = 1;
  for (const d of v) {
    const b = c >> 25;
    c = ((c & 0x1ffffff) << 5) ^ d;
    for (let i = 0; i < 5; i++) if ((b >> i) & 1) c ^= GEN[i];
  }
  return c;
};
const hrpExpand = (h) => [...[...h].map((c) => c.charCodeAt(0) >> 5), 0, ...[...h].map((c) => c.charCodeAt(0) & 31)];
const toBytes = (words, pad) => {
  let acc = 0, bits = 0;
  const out = [];
  for (const v of words) {
    acc = (acc << 5) | v; bits += 5;
    while (bits >= 8) { bits -= 8; out.push((acc >> bits) & 255); }
  }
  if (pad && bits) out.push((acc << (8 - bits)) & 255);
  return Uint8Array.from(out);
};
const toInt = (words) => words.reduce((n, w) => n * 32 + w, 0);
const hex = (b) => [...b].map((x) => x.toString(16).padStart(2, "0")).join("");

const NETWORKS = [["bcrt", "regtest"], ["tbs", "signet"], ["tb", "testnet"], ["bc", "mainnet"], ["sb", "simnet"]];
const MULT = { m: 100_000_000n, u: 100_000n, n: 100n }; // millisatoshi per unit; p handled below

function parseAmount(rest) {
  if (rest === "") return null;
  const m = rest.match(/^(\d+)([munp]?)$/);
  if (!m) throw new Error("The amount part of the invoice is not valid.");
  const [, num, unit] = m;
  if (num.length > 1 && num[0] === "0") throw new Error("The amount has a leading zero, which is not allowed.");
  const n = BigInt(num);
  if (unit === "") return n * 100_000_000_000n;                       // whole bitcoin
  if (unit === "p") {
    if (n % 10n !== 0n) throw new Error("The amount is finer than one millisatoshi, which is not allowed.");
    return n / 10n;
  }
  return n * MULT[unit];
}

export async function decode(input) {
  let s = String(input || "").trim().replace(/^lightning:/i, "");
  if (!s) throw new Error("Paste an invoice first.");
  if (s !== s.toLowerCase() && s !== s.toUpperCase()) throw new Error("The invoice mixes upper and lower case, which bech32 does not allow.");
  s = s.toLowerCase();
  const sep = s.lastIndexOf("1");
  if (sep < 3 || !s.startsWith("ln")) throw new Error("This does not look like a Lightning invoice. They start with lnbc, lntb or lntbs.");
  const hrp = s.slice(0, sep);
  const words = [...s.slice(sep + 1)].map((c) => CH.indexOf(c));
  if (words.some((w) => w < 0)) throw new Error("The invoice contains a character bech32 does not use.");
  if (words.length < 6 + 7 + 104) throw new Error("The invoice is too short to hold a timestamp and a signature.");
  if (polymod([...hrpExpand(hrp), ...words]) !== 1) throw new Error("The checksum does not match. The invoice was mistyped or altered.");

  const body = hrp.slice(2);
  const net = NETWORKS.find(([p]) => body.startsWith(p));
  if (!net) throw new Error(`Unknown network prefix "${hrp}".`);
  const amountMsat = parseAmount(body.slice(net[0].length));

  const data = words.slice(0, -6);
  const tagged = data.slice(0, -104);
  const sigWords = data.slice(-104);
  const timestamp = toInt(tagged.slice(0, 7));

  const f = { unknown: 0 };
  for (let i = 7; i < tagged.length;) {
    const tag = CH[tagged[i]];
    const len = tagged[i + 1] * 32 + tagged[i + 2];
    const d = tagged.slice(i + 3, i + 3 + len);
    if (i + 3 + len > tagged.length) throw new Error("A field runs past the end of the invoice.");
    i += 3 + len;
    switch (tag) {
      case "p": if (len === 52) f.paymentHash = hex(toBytes(d)); break;
      case "s": if (len === 52) f.paymentSecret = hex(toBytes(d)); break;
      case "h": if (len === 52) f.descriptionHash = hex(toBytes(d)); break;
      case "n": if (len === 53) f.payee = hex(toBytes(d)); break;
      case "d": f.description = new TextDecoder().decode(toBytes(d)); break;
      case "x": f.expiry = toInt(d); break;
      case "c": f.minFinalCltv = toInt(d); break;
      case "m": f.metadata = hex(toBytes(d)); break;
      case "f": f.fallback = { 17: "P2PKH", 18: "P2SH" }[d[0]] || (d[0] === 0 ? (len === 33 ? "P2WPKH" : "P2WSH") : "segwit v" + d[0]); break;
      case "r": f.routeHops = (f.routeHops || 0) + Math.floor(toBytes(d).length / 51); break;
      case "9": {
        const bits = [];
        d.forEach((w, k) => { for (let b = 0; b < 5; b++) if ((w >> b) & 1) bits.push((d.length - 1 - k) * 5 + b); });
        f.features = bits.sort((a, b) => a - b);
        break;
      }
      default: f.unknown++;
    }
  }
  if (!f.paymentHash) throw new Error("The invoice has no payment hash.");
  if (!f.paymentSecret) throw new Error("The invoice has no payment secret, which current Lightning rules require.");

  const sig = toBytes(sigWords);
  const recovery = sig[64];
  if (recovery > 3) throw new Error("The signature's recovery flag is invalid.");
  const msg = new Uint8Array(await crypto.subtle.digest("SHA-256",
    new Uint8Array([...new TextEncoder().encode(hrp), ...toBytes(tagged, true)])));
  const compact = S.Signature.fromCompact(sig.slice(0, 64));
  let recovered;
  try { recovered = compact.addRecoveryBit(recovery).recoverPublicKey(msg).toHex(true); }
  catch { throw new Error("The signature does not recover to any public key, so it is not valid."); }

  let signatureCheck;
  if (f.payee) {
    if (compact.hasHighS()) throw new Error("The signature is in non-canonical (high-S) form while the payee key is stated, which the spec rejects.");
    if (!S.verify(compact, msg, f.payee, { lowS: true })) throw new Error("The signature does not match the payee key written in the invoice.");
    signatureCheck = "checked against the payee key written in the invoice";
  } else {
    signatureCheck = "the payee key above is recovered from it";
  }

  const expiry = f.expiry ?? 3600;
  return {
    network: net[1], prefix: hrp, amountMsat, timestamp, expiry,
    expiresAt: timestamp + expiry, minFinalCltv: f.minFinalCltv ?? 18,
    payee: f.payee || recovered, payeeStated: !!f.payee, signatureCheck,
    paymentHash: f.paymentHash, paymentSecret: f.paymentSecret,
    description: f.description ?? null, descriptionHash: f.descriptionHash ?? null,
    fallback: f.fallback ?? null, routeHops: f.routeHops ?? 0, features: f.features ?? [],
    metadata: f.metadata ?? null, unknownFields: f.unknown,
  };
}
