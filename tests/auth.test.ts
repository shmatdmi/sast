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
  assert.equal(validPassword("123456"), false);
  assert.equal(validPassword("1234567"), true);
  assert.equal(validPassword("a".repeat(256)), true);
  assert.equal(validPassword("a".repeat(257)), false);
  assert.equal(validPassword(generateTemporaryPassword()), true);
});

test("username validation rejects whitespace, injection and out-of-range lengths", () => {
  for (const username of ["", "ab", "a".repeat(65), ".admin", "-admin", "admin user", "admin\n", "admin' OR 1=1", "админ", "Admin"]) {
    assert.equal(validUsername(username), false, username);
  }
  for (const username of ["abc", "a".repeat(64), "admin.user-01", "a_b"]) assert.equal(validUsername(username), true, username);
});

test("identical passwords get independent salts and verify without normalization", async () => {
  const password = " Пароль-123 🔐 ";
  const first = await hashPassword(password);
  const second = await hashPassword(password);
  assert.notEqual(first, second);
  assert.notEqual(first.split(":")[1], second.split(":")[1]);
  assert.equal(await verifyPassword(password, first), true);
  assert.equal(await verifyPassword(password, second), true);
  assert.equal(await verifyPassword(password.trim(), first), false);
  assert.equal(await verifyPassword(password, `${first}:extra`), false);
  assert.equal(await verifyPassword(password, first.replace(":", ":!")), false);
});

test("rejects incomplete and unsupported stored password formats", async () => {
  for (const stored of ["", "plaintext", "scrypt", "scrypt::", "scrypt:salt:", "scrypt::hash", "argon2:salt:hash"]) {
    assert.equal(await verifyPassword("1234567", stored), false, stored);
  }
});

test("malformed scrypt encoding cannot authenticate an arbitrary password", async () => {
  for (const stored of ["scrypt:eA==:!!!", "scrypt:!!!:eA==", "scrypt:eA==:eA=="]) {
    assert.equal(await verifyPassword("any-password", stored), false, stored);
  }
});

test("temporary passwords are unique and satisfy the account policy", () => {
  const passwords = Array.from({ length: 50 }, () => generateTemporaryPassword());
  assert.equal(new Set(passwords).size, passwords.length);
  assert.ok(passwords.every(password => validPassword(password)));
});
