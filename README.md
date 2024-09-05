# mock-dns-server

Create a mock DNS-over-TLS server based on
[mock-tls-server](https://github.com/hildjj/mock-tls-server/).

## Installation

```sh
npm install -D mock-dns-server
```

## API

Full [API documentation](http://hildjj.github.io/mock-dns-server/) is available.

Example:

```js
import {connect, createServer} from 'mock-dns-server';

/** @type {import('mock-dns-server').Zones} */
const zones = {
  'xmpp.example.com': {
    A: ['192.168.1.2', '192.168.1.3'],
  },
  '_xmpp-server._tcp.example.com': {
    SRV: {
      priority: 30,
      weight: 30,
      port: 5269,
      target: 'xmpp.example.com',
    },
  },
};
const server = createServer({zones});

/** @type {import('node:tls').TLSSocket} */
const sock = connect(server.port);
```

---
[![Build Status](https://github.com/hildjj/mock-dns-server/workflows/Tests/badge.svg)](https://github.com/hildjj/mock-dns-server/actions?query=workflow%3ATests)
[![codecov](https://codecov.io/gh/hildjj/mock-dns-server/graph/badge.svg?token=DV71ZVU6K3)](https://codecov.io/gh/hildjj/mock-dns-server)
