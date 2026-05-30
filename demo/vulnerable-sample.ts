// Demo file — every line below should trigger a Risk Firewall finding.
// Open this in the Extension Development Host to see the watcher light up.

const OPENAI_KEY = "sk-proj-abc123def456ghi789jkl012mno345pqr"; // risk-firewall-ignore-line
const stripeSecret = "sk_test_51AbCdEfGhIjKlMnOpQrStUvodemo1234"; // risk-firewall-ignore-line
const password = "hunter2supersecret"; // risk-firewall-ignore-line
// risk-firewall-ignore-line

export function render(userInput: string) {
  document.body.innerHTML = userInput; // xss
  eval(userInput); // injection 


}

// 12ew

const corsOptions = { origin: "*", credentials: true }; // cors

const httpsAgent = { rejectUnauthorized: false }; // tls off

console.log("login password:", password); // logs a secret

const query = `SELECT * FROM users WHERE id = ${userInputId}`; // sql injection

import jwt from "jsonwebtoken";
const token = jwt.sign({ id: 1 }, "myhardcodedsecret"); // weak jwt
declare const userInputId: string;
