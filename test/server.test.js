import * as packet from 'dns-packet';
import {connect, createServer} from '../lib/index.js';
import {equal, notEqual, ok} from 'node:assert/strict';
import {DNS} from './zone.js';
import {NoFilter} from 'nofilter';
import {pEvent} from 'p-event';
// eslint-disable-next-line n/no-unsupported-features/node-builtins
import test from 'node:test';

function like(actual, expected, message) {
  ok(actual, message);
  ok(expected, message);
  for (const [k, v] of Object.entries(expected)) {
    equal(actual[k], v, `${message} [${k}] ${actual[k]} != ${v}`);
  }
}

test('server', async() => {
  const server = createServer({zones: DNS});
  ok(server);
  const cli = connect(server.port);
  ok(cli);
  await pEvent(cli, 'secure');
  const nof = new NoFilter();
  cli.pipe(nof);

  const query = {
    type: 'query',
    id: 17,
    flags: packet.RECURSION_DESIRED,
    questions: [{
      type: 'A',
      class: 'IN',
      name: 'ietf.org',
    }],
  };
  cli.write(packet.streamEncode(query));
  const sz = (await nof.readFull(2)).readUint16BE();
  const dresp = packet.decode(await nof.readFull(sz));
  equal(dresp.id, 17, 'packet ID');
  like(dresp.answers[0], {
    data: '104.16.44.99',
    name: 'ietf.org',
    type: 'A',
  }, 'response 1');

  query.questions[0].name = 'chunky.example';
  query.additionals = [{
    name: '.',
    type: 'OPT',
    // @ts-ignore TS2339: types not up to date
    udpPayloadSize: 4096,
    flags: 0,
    options: [{
      code: 'PADDING',
      length: 10, // Just for test
    }],
  }];

  const qbuf = packet.streamEncode(query);
  // Sorry for callback hell.  Ensure we don't get Nagle'd.
  cli.write(qbuf.slice(0, 1), () => {
    cli.write(qbuf.slice(1, 3), () => {
      cli.write(qbuf.slice(3, 7), () => {
        cli.write(qbuf.slice(7));
      });
    });
  });
  const sz2 = (await nof.readFull(2)).readUint16BE();
  const dresp2 = packet.decode(await nof.readFull(sz2));
  ok(dresp2);
  like(dresp2.answers[0], {
    data: '192.168.1.1',
    name: 'chunky.example',
    type: 'A',
  }, 'response 2');

  query.questions[0].name = 'badid.example';
  cli.write(packet.streamEncode(query));
  const sz3 = (await nof.readFull(2)).readUint16BE();
  const dresp3 = packet.decode(await nof.readFull(sz3));
  notEqual(dresp3.id, 17);

  query.questions[0].name = 'unknown.invalid';
  cli.write(packet.streamEncode(query));
  const sz4 = (await nof.readFull(2)).readUint16BE();
  const dresp4 = packet.decode(await nof.readFull(sz4));
  equal(dresp4.rcode, 'NXDOMAIN');
  cli.end();
  await pEvent(cli, 'end');

  server.close();
  await pEvent(server, 'close');
});
