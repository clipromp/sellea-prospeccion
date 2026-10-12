// Uso: node scripts/hash.mjs "contraseña"  → imprime el valor para ADMIN_CLAVE_HASH
import crypto from "node:crypto";
const pass = process.argv[2];
if (!pass) { console.error('Uso: node scripts/hash.mjs "contraseña"'); process.exit(1); }
const salt = crypto.randomBytes(16).toString("hex");
console.log("scrypt$" + salt + "$" + crypto.scryptSync(pass, salt, 32).toString("hex"));
