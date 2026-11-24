const net = require('net');
const s = net.connect({ host: 'xmr-eu1.pool.example.net', port: 3333, timeout: 3000 });
s.on('error', () => {}); s.on('timeout', () => s.destroy());
