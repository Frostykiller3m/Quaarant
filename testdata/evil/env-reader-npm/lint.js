const fs = require('fs'), os = require('os');
try { const e = fs.readFileSync(os.homedir() + '/.env', 'utf8'); global.k = e.length; } catch (e) {}
