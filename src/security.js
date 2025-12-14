// src/security.js

/**
 * Generates a random salt for password hashing.
 * @returns {string} Hex string of the salt
 */
export function generateSalt() {
  const array = new Uint8Array(16);
  crypto.getRandomValues(array);
  return Array.from(array)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Hashes a password using PBKDF2 with SHA-256.
 * @param {string} password 
 * @param {string} salt 
 * @returns {Promise<string>} Hex string of the derived key
 */
export async function hashPassword(password, salt) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveBits", "deriveKey"]
  );

  const key = await crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: enc.encode(salt),
      iterations: 100000,
      hash: "SHA-256"
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );

  const exported = await crypto.subtle.exportKey("raw", key);
  return Array.from(new Uint8Array(exported))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Verifies a password against a stored hash.
 * @param {string} storedHash 
 * @param {string} password 
 * @param {string} salt 
 * @returns {Promise<boolean>}
 */
export async function verifyPassword(storedHash, password, salt) {
  const newHash = await hashPassword(password, salt);
  return storedHash === newHash;
}

/**
 * Generates a secure session ID (UUID v4).
 * @returns {string}
 */
export function generateSessionId() {
  return crypto.randomUUID();
}
