// Benchmark Corpus: SAST Vulnerabilities
const express = require('express');
const { exec } = require('child_process');
const fs = require('fs');
const db = require('./fake-db');

const app = express();

// 1. SQL Injection
app.get('/user', (req, res) => {
  const userId = req.query.id;
  const query = "SELECT * FROM users WHERE id = " + userId;
  db.query(query);
});

// 2. Command Injection
app.get('/ping', (req, res) => {
  const host = req.query.host;
  exec(`ping -c 1 ${host}`);
});

// 3. DOM XSS / Insecure innerHTML
function renderUserBio(bio) {
  document.getElementById('bio').innerHTML = bio;
}

// 4. Path Traversal
app.get('/download', (req, res) => {
  const filename = req.query.file;
  fs.readFileSync('/var/data/' + filename);
});

// 5. SSRF
app.get('/proxy', (req, res) => {
  const target = req.query.url;
  fetch(target);
});

// 6. Insecure Deserialization
const serialize = require('node-serialize');
app.post('/profile', (req, res) => {
  serialize.unserialize(req.body.data);
});

// 7. Dynamic Code Execution (eval)
app.post('/calc', (req, res) => {
  eval(req.body.expr);
});

// 8. ReDoS
const redosRegex = /(a+)+$/;

// 9. Weak Cryptography (MD5)
const crypto = require('crypto');
const hash = crypto.createHash('md5').update('data').digest('hex');

// 10. Insecure RNG for Security Token
const token = Math.random().toString(36).substring(2);
