// Mailbox cryptography of the relay (HNK-23.T4, P-04), with Node's built-in crypto only.
//
// mailbox_id = BLAKE2b-512("JitsuinMailboxId_v1\n" ‖ mailbox_pk)[0..32]
//   The relay computes it from the key, so the id it stores is the client's (BL-D21-08).
//
// Ownership proof, for registering a mailbox and for reading it (BL-D21-08, BL-D21-09):
//   the relay makes a one-time ephemeral X25519 key e and a 32-byte nonce;
//   shared = X25519(e_secret, mailbox_pk) = X25519(mailbox_secret, e_public);
//   proof  = BLAKE2b-512("JitsuinMailboxProof_v1\n" ‖ purpose ‖ 0x00 ‖ shared ‖ nonce ‖ mailbox_pk)[0..32].
//   Only the holder of the mailbox secret can compute it, so knowing mailbox_id or mailbox_pk is
//   not enough to register a mailbox or to list its messages. BLAKE2b is not length-extendable,
//   so the prefix construction is a MAC here.
import { createHash, createPrivateKey, createPublicKey, diffieHellman, generateKeyPairSync, randomBytes, timingSafeEqual, type KeyObject } from "node:crypto";

export type Purpose = "register" | "read";

const ID_DOMAIN = Buffer.from("JitsuinMailboxId_v1\n");
const PROOF_DOMAIN = Buffer.from("JitsuinMailboxProof_v1\n");

export function fromHex(hex: string, bytes: number, what: string): Buffer {
  if (typeof hex !== "string" || hex.length !== bytes * 2 || !/^[0-9a-f]+$/.test(hex)) {
    throw new BadRequest(`${what} must be ${bytes * 2} lowercase hex characters`);
  }
  return Buffer.from(hex, "hex");
}

export class BadRequest extends Error {}

export function mailboxId(mailboxPk: Buffer): string {
  return createHash("blake2b512").update(ID_DOMAIN).update(mailboxPk).digest().subarray(0, 32).toString("hex");
}

export function publicKeyFromRaw(raw: Buffer): KeyObject {
  return createPublicKey({ key: { kty: "OKP", crv: "X25519", x: raw.toString("base64url") }, format: "jwk" });
}

export function privateKeyFromRaw(secret: Buffer, publicRaw: Buffer): KeyObject {
  return createPrivateKey({ key: { kty: "OKP", crv: "X25519", d: secret.toString("base64url"), x: publicRaw.toString("base64url") }, format: "jwk" });
}

export function rawPublic(k: KeyObject): Buffer {
  return Buffer.from(k.export({ format: "jwk" }).x as string, "base64url");
}

export function rawSecret(k: KeyObject): Buffer {
  return Buffer.from(k.export({ format: "jwk" }).d as string, "base64url");
}

/** A fresh ephemeral key for one challenge. */
export function ephemeral(): { secret: Buffer; public: Buffer } {
  const { privateKey, publicKey } = generateKeyPairSync("x25519");
  return { secret: rawSecret(privateKey), public: rawPublic(publicKey) };
}

/** X25519; refuses low-order keys, whose shared secret is all zero and proves nothing. */
export function x25519(secret: Buffer, secretPublic: Buffer, peerPublic: Buffer): Buffer {
  let shared: Buffer;
  try {
    shared = diffieHellman({ privateKey: privateKeyFromRaw(secret, secretPublic), publicKey: publicKeyFromRaw(peerPublic) });
  } catch {
    throw new BadRequest("mailbox_pk is not a usable X25519 key");
  }
  if (shared.every((b) => b === 0)) throw new BadRequest("mailbox_pk is not a usable X25519 key");
  return shared;
}

export function proofTag(purpose: Purpose, shared: Buffer, nonce: Buffer, mailboxPk: Buffer): Buffer {
  return createHash("blake2b512")
    .update(PROOF_DOMAIN)
    .update(purpose)
    .update(Buffer.of(0))
    .update(shared)
    .update(nonce)
    .update(mailboxPk)
    .digest()
    .subarray(0, 32);
}

export function sameBytes(a: Buffer, b: Buffer): boolean {
  return a.length === b.length && timingSafeEqual(a, b);
}

export function randomToken(): string {
  return randomBytes(32).toString("base64url");
}

export function tokenHash(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

export { randomBytes };
