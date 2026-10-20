// HNK-23.T2: the relay accepts what jitsuin-wasm computes. Same vector as jitsuinfi-zcash
// crates/jitsuin-core/src/mailbox.rs `vector_matches_the_relay` (PRF output 0x11 × 32, relay
// ephemeral secret 0x22 × 32, nonce 0x33 × 32).
import { test } from "node:test";
import assert from "node:assert/strict";
import { createPrivateKey, createPublicKey } from "node:crypto";
import { mailboxId, proofTag, rawPublic, rawSecret, x25519 } from "../src/crypto.ts";

const MAILBOX_PK = "721e61a2e3a16f2e7806c392b1367c8edb7c11c0132d2b5d3164290d60fce400";
const MAILBOX_ID = "171e3bf4c1a8af89725083cc6ceac9bb9400ebcf9caac626f1b6779e667559c2";
const EPH_PK = "0faa684ed28867b97f4a6a2dee5df8ce974e76b7018e3f22a1c4cf2678570f20";
const PROOF_REGISTER = "7d4a818d24e88f5a20279120ae3dad9e64409b7f9b0de59b415ce565ef84f7a2";

test("the relay computes the client's mailbox_id and accepts its proof", () => {
  const pk = Buffer.from(MAILBOX_PK, "hex");
  assert.equal(mailboxId(pk), MAILBOX_ID);
  const e = createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b656e04220420", "hex"), Buffer.alloc(32, 0x22)]), format: "der", type: "pkcs8" });
  const ePub = rawPublic(createPublicKey(e));
  assert.equal(ePub.toString("hex"), EPH_PK);
  const shared = x25519(rawSecret(e), ePub, pk);
  assert.equal(proofTag("register", shared, Buffer.alloc(32, 0x33), pk).toString("hex"), PROOF_REGISTER);
  assert.notEqual(proofTag("read", shared, Buffer.alloc(32, 0x33), pk).toString("hex"), PROOF_REGISTER);
});
