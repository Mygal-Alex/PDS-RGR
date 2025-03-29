require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');

const app = express();
app.use(bodyParser.json());

const PORT = process.env.PORT || 3000;
const RSA_KEY_LENGTH = parseInt(process.env.RSA_KEY_LENGTH || '2048');

// Генеруємо випадковий рядок сервера та пару ключів
let serverRandom = crypto.randomBytes(32).toString('hex');
let { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: RSA_KEY_LENGTH,
});

let sessionKey;

// Відповідь сервера з public key та server random
app.post('/hello', (req, res) => {
  const { clientRandom } = req.body;
  console.log('Сервер отримав повідомлення "hello" від клієнта:', clientRandom);
  console.log('Сервер надсилає "server hello" та відкритий ключ...');

  return res.json({
    serverRandom,
    publicKey: publicKey.export({ type: 'pkcs1', format: 'pem' })
  });
});

//Прийом зашифрованого premaster та розшифрування
app.post('/premaster', (req, res) => {
  const { encryptedPremaster } = req.body;
  const premasterSecret = crypto.privateDecrypt(
    privateKey,
    Buffer.from(encryptedPremaster, 'base64')
  );

  console.log('Сервер розшифрував premaster secret:', premasterSecret.toString('hex'));

  //Генерація session key
  sessionKey = crypto.createHash('sha256')
    .update(serverRandom + premasterSecret.toString('hex'))
    .digest();

  console.log('Сервер згенерував session key:', sessionKey.toString('hex'));

  return res.sendStatus(200);
});

// Прийом "ready" від клієнта та відповідь "ready"
app.post('/ready', (req, res) => {
  const { encryptedReady } = req.body;
  const decipher = crypto.createDecipheriv('aes-256-cbc', sessionKey, sessionKey.subarray(0, 16));
  let decrypted = decipher.update(encryptedReady, 'base64', 'utf8');
  decrypted += decipher.final('utf8');
  console.log('Сервер отримав повідомлення "ready" від клієнта (розшифровано):', decrypted);

  const cipher = crypto.createCipheriv('aes-256-cbc', sessionKey, sessionKey.subarray(0, 16));
  let encrypted = cipher.update('ready', 'utf8', 'base64');
  encrypted += cipher.final('base64');
  console.log('Сервер надсилає зашифроване повідомлення "ready" клієнту');

  return res.json({ encryptedReady: encrypted });
});

// Прийом зашифрованого повідомлення після handshake
app.post('/secure', (req, res) => {
  const { encryptedMessage } = req.body;
  const decipher = crypto.createDecipheriv('aes-256-cbc', sessionKey, sessionKey.subarray(0, 16));
  let decrypted = decipher.update(encryptedMessage, 'base64', 'utf8');
  decrypted += decipher.final('utf8');
  console.log('Сервер отримав зашифроване повідомлення від клієнта (розшифровано):', decrypted);

  return res.sendStatus(200);
});

app.listen(PORT, () => console.log(`server running on port ${PORT}`));