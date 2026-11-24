const test = require('node:test'), assert = require('assert'), add = require('./index');
test('adds', () => assert.strictEqual(add(2, 3), 5));
