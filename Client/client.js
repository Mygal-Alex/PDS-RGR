require('dotenv').config();
const axios = require('axios');
const crypto = require('crypto');

const SERVER_URL = process.env.SERVER_URL;
const PREMASTER_LENGTH = parseInt(process.env.PREMASTER_LENGTH || '48');

(async () => {
  //Клієнт ініціює рукостискання (client hello)
  const clientRandom = crypto.randomBytes(32).toString('hex');
  console.log('Клієнт надсилає "hello" з випадковим рядком:', clientRandom);

  // Отримує server hello та public key
  const helloRes = await axios.post(`${SERVER_URL}/hello`, { clientRandom });
  const { serverRandom, publicKey } = helloRes.data;
  console.log('Клієнт отримав "server hello" і відкритий ключ');
  console.log('Отриманий випадковий рядок від сервера:', serverRandom);

  // Генерація premaster та шифрування  public key
  const premasterSecret = crypto.randomBytes(PREMASTER_LENGTH);
  console.log('Клієнт згенерував premaster secret:', premasterSecret.toString('hex'));
  const encryptedPremaster = crypto.publicEncrypt(publicKey, premasterSecret);

  await axios.post(`${SERVER_URL}/premaster`, {
    encryptedPremaster: encryptedPremaster.toString('base64')
  });
  console.log('Клієнт надіслав зашифрований premaster секрет серверу');

  //Генерація session key
  const sessionKey = crypto.createHash('sha256')
    .update(serverRandom + premasterSecret.toString('hex'))
    .digest();
  console.log('Клієнт згенерував session key:', sessionKey.toString('hex'));

  //Клієнт надсилає "ready"
  const cipher = crypto.createCipheriv('aes-256-cbc', sessionKey, sessionKey.subarray(0, 16));
  let encrypted = cipher.update('ready', 'utf8', 'base64');
  encrypted += cipher.final('base64');
  console.log('Клієнт надсилає зашифроване повідомлення "ready" серверу...');

  //Отримує "ready" від сервера
  const readyRes = await axios.post(`${SERVER_URL}/ready`, { encryptedReady: encrypted });
  const { encryptedReady: encryptedBack } = readyRes.data;
  console.log('Клієнт отримав зашифроване повідомлення "ready" від сервера');

  const decipher = crypto.createDecipheriv('aes-256-cbc', sessionKey, sessionKey.subarray(0, 16));
  let decrypted = decipher.update(encryptedBack, 'base64', 'utf8');
  decrypted += decipher.final('utf8');
  console.log('Клієнт розшифрував повідомлення "ready" від сервера:', decrypted);

  //Відправлення зашифрованого повідомлення після handshake
  const message = 'Привіт! Це секретне повідомлення.';
  const msgCipher = crypto.createCipheriv('aes-256-cbc', sessionKey, sessionKey.subarray(0, 16));
  let encryptedMsg = msgCipher.update(message, 'utf8', 'base64');
  encryptedMsg += msgCipher.final('base64');

  console.log('Клієнт надсилає зашифроване повідомлення:', message);
  await axios.post(`${SERVER_URL}/secure`, { encryptedMessage: encryptedMsg });
  console.log('Клієнт успішно надіслав зашифроване повідомлення');
})();
