const test = require('node:test'), assert = require('assert'), fs = require('fs');
test('built', () => assert.match(fs.readFileSync('dist/index.html', 'utf8'), /site-qt/));
