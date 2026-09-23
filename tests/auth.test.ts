import assert from "node:assert/strict";
import test from "node:test";
import { generateTemporaryPassword, hashPassword, normalizeUsername, validPassword, validUsername, verifyPassword } from "../app/lib/auth-crypto.ts";

test("hashes and verifies passwords without storing plaintext", async () => {
  const password = "Long-enough-password-42!";
  const hash = await hashPassword(password);
  assert.notEqual(hash, password);
  assert.match(hash, /^scrypt:/);
  assert.equal(await verifyPassword(password, hash), true);
  assert.equal(await verifyPassword("wrong-password", hash), false);
});

test("validates account credentials and generates usable temporary passwords", () => {
  assert.equal(normalizeUsername("  Admin.User  "), "admin.user");
  assert.equal(validUsername("admin.user"), true);
  assert.equal(validUsername("no"), false);
  assert.equal(validPassword("short"), false);
  assert.equal(validPassword(generateTemporaryPassword()), true);
});
