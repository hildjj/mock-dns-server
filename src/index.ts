import * as packet from 'dns-packet';
// @ts-expect-error Incomplete types
// eslint-disable-next-line n/no-missing-import
import * as rcodes from 'dns-packet/rcodes.js';
import {MockTLSServer, type ServerOpts} from 'mock-tls-server';
import type {Buffer} from 'node:buffer';
import {NoFilter} from 'nofilter';
import type {TLSSocket} from 'node:tls';
import assert from 'node:assert';

export {connect, plainConnect} from 'mock-tls-server';

const PAD_SIZE = 468; // See RFC 8467
const AA = 1 << 10;
const CONNECTION = Symbol('connection');

export interface ConnectionOptions {
  zones?: Zones;
}

export type MockDNSServerOptions = ConnectionOptions & {
  port?: number;
};

export interface Zone1 {
  A: string;
  AAAA: string;
  AFSDB: Buffer;
  APL: Buffer;
  AXFR: Buffer;
  CAA: packet.CaaData;
  CDNSKEY: Buffer;
  CDS: Buffer;
  CERT: Buffer;
  CNAME: string;
  DNAME: string;
  DHCID: Buffer;
  DLV: Buffer;
  DNSKEY: packet.DnskeyData;
  DS: packet.DsData;
  HINFO: packet.HInfoAnswer;
  HIP: Buffer;
  IXFR: Buffer;
  IPSECKEY: Buffer;
  KEY: Buffer;
  KX: Buffer;
  LOC: Buffer;
  MX: packet.MxAnswer;
  NAPTR: packet.NaptrAnswer;
  NS: string;
  NSEC: packet.NsecAnswer;
  NSEC3: packet.Nsec3Answer;
  NSEC3PARAM: Buffer;
  NULL: Buffer;
  OPT: never;
  PTR: string;
  RRSIG: packet.RrsigData;
  RP: packet.RpData;
  SIG: Buffer;
  SOA: packet.SoaData;
  SRV: packet.SrvData;
  SSHFP: packet.SshfpData;
  TA: Buffer;
  TKEY: Buffer;
  TLSA: packet.TlsaData;
  TSIG: Buffer;
  TXT: packet.TxtData;
  URI: Buffer;
}

export type Zone = {
  [rtype in keyof Zone1]?: Zone1[rtype] | Zone1[rtype][] | undefined;
};

export interface Zones {
  [key: string]: Zone;
}

class Connection {
  public zones: Zones;
  #sock: TLSSocket;
  #size: number;
  #nof: NoFilter;

  public constructor(sock: TLSSocket, options: ConnectionOptions) {
    const opts: Required<ConnectionOptions> = {
      zones: {},
      ...options,
    };

    this.#sock = sock;
    this.#size = -1;
    this.#nof = new NoFilter();
    this.zones = opts.zones;
    this.#sock.on('data', this._data.bind(this));
  }

  private _data(chunk: Buffer): void {
    this.#nof.write(chunk);

    while (this.#nof.length > 0) {
      if (this.#size === -1) {
        if (this.#nof.length < 2) {
          return;
        }
        this.#size = this.#nof.readUInt16BE();
      }
      if (this.#nof.length < this.#size) {
        return;
      }
      const buf = this.#nof.read(this.#size) as Buffer;
      this.#size = -1;
      const pkt = packet.decode(buf);
      let chunky = false;
      assert(pkt.id !== undefined);
      assert(pkt.questions);

      const rp: packet.Packet = {
        id: pkt.id,
        type: 'response',
        flags: AA,
        questions: pkt.questions,
        answers: [],
      };

      for (const {name, type} of pkt.questions) {
        if (/badid/i.test(name)) {
          rp.id = (pkt.id + 1) % 65536;
        }
        if (/chunky/.test(name)) {
          chunky = true;
        }

        const domain = this.zones[name];
        if (domain) {
          const data = [domain[type]].flat();
          for (const d of data) {
            const ans = {
              name,
              type,
              class: 'IN',
              ttl: 1000,
              data: d,
            } as packet.Answer;
            rp.answers?.push(ans);
          }
        }
      }

      if (!rp.answers?.length) {
        rp.flags = AA | rcodes.toRcode('NXDOMAIN');
      }

      // Only pad if client said they support EDNS0
      if (pkt.additionals?.find(a => a.type === 'OPT')) {
        const unpadded = packet.encodingLength(rp);
        const opt: packet.OptAnswer = {
          name: '.',
          type: 'OPT',
          udpPayloadSize: 4096,
          flags: 0,
          options: [{
            code: 12, // PADDING
            length: (Math.ceil(unpadded / PAD_SIZE) * PAD_SIZE) -
              unpadded - 4,
          }],
          ednsVersion: 0,
          extendedRcode: 0,
          flag_do: false,
        };
        rp.additionals = [opt];
      }

      const reply = packet.streamEncode(rp);
      if (chunky) {
        // Write in chunks, for testing reassembly
        // Avoid Nagle by going full-sync
        this.#sock.write(reply.subarray(0, 1), () => {
          this.#sock.write(reply.subarray(1, 2), () => {
            this.#sock.write(reply.subarray(2, 7), () => {
              this.#sock.write(reply.subarray(7));
            });
          });
        });
      } else {
        this.#sock.write(reply);
      }
    }
  }
}

/**
 * Create a mock DNS server.
 *
 * @param [options] Any options for mock-tls-server.  Port defaults
 *   to 853.
 * @returns The created server, already listening.
 */
export function createServer(
  options: MockDNSServerOptions & ServerOpts = {}
): MockTLSServer {
  const {port = 853, zones = {}, ...opts} = options;
  const server = new MockTLSServer(opts);
  server.listen(port, (cli: TLSSocket) => {
    // @ts-expect-error Lifetime of server tied to client
    cli[CONNECTION] = new Connection(cli, {zones});
  });
  return server;
}
