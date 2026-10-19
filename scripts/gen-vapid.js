// Generates VAPID keys ONCE into .vapid.json (mode 600). Never prints the keys.
const fs = require('fs');
const path = require('path');
const webpush = require('web-push');

const p = path.join(__dirname, '..', '.vapid.json');
if (fs.existsSync(p)) {
  console.log('vapid: already exists, keeping it');
} else {
  const keys = webpush.generateVAPIDKeys();
  fs.writeFileSync(p, JSON.stringify(keys), { mode: 0o600 });
  console.log('vapid: generated');
}
