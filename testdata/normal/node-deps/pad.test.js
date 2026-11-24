const test = require('node:test'), assert = require('assert'), lp = require('left-pad');
test('pads', () => assert.strictEqual(lp('7', 3, '0'), '007'));
