import { randomBytes, scrypt as scryptCallback, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";

const scrypt = promisify(scryptCallback);
export function normalizeUsername(value: string) { return value.trim().toLowerCase(); }
export function validUsername(value: string) { return /^[a-z0-9][a-z0-9._-]{2,63}$/.test(value); }
export function validPassword(value: string) { return value.length >= 10 && value.length <= 256; }
export async function hashPassword(password: string) { const salt = randomBytes(16); const derived = await scrypt(password, salt, 64) as Buffer; return `scrypt:${salt.toString("base64")}:${derived.toString("base64")}`; }
export async function verifyPassword(password: string, stored: string) { const [algorithm, saltValue, hashValue] = stored.split(":"); if (algorithm !== "scrypt" || !saltValue || !hashValue) return false; const expected = Buffer.from(hashValue, "base64"); const actual = await scrypt(password, Buffer.from(saltValue, "base64"), expected.length) as Buffer; return actual.length === expected.length && timingSafeEqual(actual, expected); }
export function generateTemporaryPassword() { return `${randomBytes(9).toString("base64url")}A1!`; }
