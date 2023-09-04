// Ported from https://www.npmjs.com/package/@glif/filecoin-address to reduce file size

import { b32decode, b32encode, hex2a } from "crypto-addr-codec";
import { blake2b } from "@noble/hashes/blake2b";
import Bn from 'bn.js'

function validateChecksum(ingest: Buffer, expect: Buffer) {
  const digest = getChecksum(ingest);
  return Buffer.compare(Buffer.from(digest), expect);
}

function getChecksum(ingest: Buffer): Uint8Array {
  return blake2b(Uint8Array.from(ingest), { dkLen: 4 });
}

function checkAddressString(address: string) {
  if (!address) {
    throw Error("No bytes to validate.");
  }
  if (address.length < 3) {
    throw Error("Address is too short to validate.");
  }
  if (address[0] !== "f" && address[0] !== "t") {
    throw Error("Unknown address network.");
  }

  switch (address[1]) {
    case "0": {
      if (address.length > 22) {
        throw Error("Invalid ID address length.");
      }
      break;
    }
    case "1": {
      if (address.length !== 41) {
        throw Error("Invalid secp256k1 address length.");
      }
      break;
    }
    case "2": {
      if (address.length !== 41) {
        throw Error("Invalid Actor address length.");
      }
      break;
    }
    case "3": {
      if (address.length !== 86) {
        throw Error("Invalid BLS address length.");
      }
      break;
    }
    default: {
      throw new Error("Invalid address protocol.");
    }
  }
}

function filDecode(address: string) {
  checkAddressString(address);
  const network = address[0];
  const protocol = parseInt(address[1], 10);
  const protocolByte = Buffer.from([protocol]);
  const raw = address.slice(2);

  if (protocol === 0) {
    return filNewAddress(protocol, Buffer.from(lebEncode(raw)));
  }

  const payloadChecksum = Buffer.from(b32decode(raw.toUpperCase()));
  const { length } = payloadChecksum;
  const payload = payloadChecksum.slice(0, length - 4);
  const checksum = payloadChecksum.slice(length - 4, length);
  if (validateChecksum(Buffer.concat([protocolByte, payload]), checksum)) {
    throw Error("Checksums don't match");
  }

  const addressObj = filNewAddress(protocol, payload);
  if (filEncode(network, addressObj) !== address) {
    throw Error(`Did not encode this address properly: ${address}`);
  }
  return addressObj;
}

function filEncode(network: string, address: Address) {
  if (!address || !address.str) {
    throw Error("Invalid address");
  }
  let addressString = "";
  const payload = address.payload();
  const protocol = address.protocol();

  switch (protocol) {
    case 0: {
      const decoded = lebDecode(payload);
      addressString = network + String(protocol) + decoded;
      break;
    }
    default: {
      const protocolByte = Buffer.from([protocol]);
      const toChecksum = Buffer.concat([protocolByte, payload]);
      const checksum = getChecksum(toChecksum);
      const bytes = Buffer.concat([payload, Buffer.from(checksum)]);
      const bytes2a = hex2a(bytes.toString("hex"));
      const bytes32encoded = b32encode(bytes2a).replace(/=/g, "").toLowerCase();
      addressString = String(network) + String(protocol) + bytes32encoded;
      break;
    }
  }
  return addressString;
}

function filNewAddress(protocol: number, payload: Uint8Array): Address {
  const protocolByte = Buffer.from([protocol]);
  const input = Buffer.concat([protocolByte, payload]);
  return new Address(input);
}

export function filAddrEncoder(data: Uint8Array): string {
  const address = filNewAddress(data[0], data.slice(1));
  return filEncode("f", address).toString();
}

export function filAddrDecoder(data: string): Buffer {
  return filDecode(data).str;
}

class Address {
  public str: Buffer;
  constructor(str: Buffer) {
    if (!str || str.length < 1) {
      throw new Error("Missing str in address");
    }
    this.str = str;
  }

  // https://beta.spec.filecoin.io/#appendix__address__protocol-indicator
  public protocol(): number {
    if (this.str.length < 1) {
      throw Error("No address found.");
    }

    return this.str[0];
  }

  public payload(): Buffer {
    if (this.str.length < 1) {
      throw Error("No address found.");
    }
    return this.str.slice(1, this.str.length);
  }
}



class Stream {
  public buffer: Buffer;
  private bytesRead: number;

  constructor(buf: Buffer = Buffer.from([])) {
    this.buffer = buf;
    this.bytesRead = 0;
  }

  public read(size: number) {
    const data = this.buffer.slice(0, size);
    this.buffer = this.buffer.slice(size);
    this.bytesRead += size;
    return data;
  }

  public write(buf: [any]) {
    this.buffer = Buffer.concat([this.buffer, Buffer.from(buf)]);
  }
}

// https://gitlab.com/mjbecze/leb128/-/blob/master/unsigned.js
function read(stream: Stream) {
  return readBn(stream).toString();
}

function readBn(stream: Stream) {
  const num = new Bn(0);
  let shift = 0;
  let byt;
  while (true) {
    byt = stream.read(1)[0];
    /* tslint:disable:no-bitwise */
    num.ior(new Bn(byt & 0x7f).shln(shift));
    if (byt >> 7 === 0) {
      break;
    } else {
      shift += 7;
    }
  }
  return num;
}

function write(num: string | number, stream: Stream) {
  const bigNum = new Bn(num);
  while (true) {
    const i = bigNum.maskn(7).toNumber();
    bigNum.ishrn(7);
    if (bigNum.isZero()) {
      stream.write([i]);
      break;
    } else {
      stream.write([i | 0x80]);
    }
  }
}

/**
 * LEB128 encodeds an interger
 * @param {String|Number} num
 * @return {Buffer}
 */
export function lebEncode(num: string | number) {
  const stream = new Stream();
  write(num, stream);
  return stream.buffer;
}

/**
 * decodes a LEB128 encoded interger
 * @param {Buffer} buffer
 * @return {String}
 */
export function lebDecode(buffer: Buffer) {
  const stream = new Stream(buffer);
  return read(stream);
}
