import {Buffer} from 'node:buffer';
import {DNS} from './zone.js';
import assert from 'node:assert';
import {connect} from 'mock-tls-server';
import {createServer} from '../lib/index.js';
// eslint-disable-next-line n/no-unsupported-features/node-builtins
import test from 'node:test';

test('index', () => new Promise((resolve, reject) => {
  const s = createServer({
    zones: DNS,
  });
  const cli = connect(853, () => {
    cli.on('data', b => {
      assert(b.length > 0);
      s.close(() => resolve());
      resolve();
    });
    cli.on('error', reject);
    const req = Buffer.from('001a1c9e010000010000000000000469657466036f72670000010001', 'hex');
    cli.end(req);
  });
}));
