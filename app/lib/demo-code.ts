export const demoCode = `const express = require('express');
const { exec } = require('child_process');
const app = express();

const API_KEY = "sk_live_51N8exampleSecretKey";

app.get('/users', async (req, res) => {
  const query = "SELECT * FROM users WHERE name = '" + req.query.name + "'";
  const users = await db.query(query);
  res.json(users);
});

app.get('/diagnostics', (req, res) => {
  exec(\`ping -c 1 \${req.query.host}\`, (error, stdout) => {
    res.send(stdout);
  });
});

app.post('/preview', (req, res) => {
  document.getElementById('preview').innerHTML = req.body.content;
});`;
