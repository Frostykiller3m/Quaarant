const fs = require('fs');
fs.mkdirSync('dist', { recursive: true });
fs.writeFileSync('dist/index.html', '<h1>' + require('./package.json').name + '</h1>\n');
