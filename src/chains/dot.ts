import bs58 from 'bs58';
import { blake2b } from 'blakejs';
import { concatBytes } from "@noble/hashes/utils";

export function dotAddrEncoder(data: Uint8Array): string {
  return ss58Encode(data, 0);
}

export function ksmAddrDecoder(data: string): Uint8Array {
  return ss58Decode(data);
}

const DEFAULT_TYPE = 42;
const KNOWN_TYPES = [0, 1, 2, 42, 43, 68, 69];
const PREFIX = stringToBytes('SS58PRE');

class AccountIndex extends Number {
  toJSON() {
    return { _type: 'AccountIndex', data: this+0 }
  }
}

function stringToBytes(s: string) {
  var data = new Uint8Array(s.length);
  for (var i = 0; i < s.length; i++){
    data[i] = s.charCodeAt(i);
  }
  return data;
}

/* tslint:disable:no-bitwise */
function toLE(val: number, bytes: any) {
  let flip = false;
  if (val < 0) {
    val = -val - 1;
    flip = true;
  }

  let r = new Uint8Array(bytes);
  for (var o = 0; o < bytes; ++o) {
    r[o] = val % 256;
    if (flip) {
      r[o] = ~r[o] & 0xff;
    }
    val /= 256;
  }
  return r;
}

function leToNumber(le) {
  let r = 0;
  let a = 1;
  le.forEach(x => { r += x * a; a *= 256; });
  return r;
}

function mergeUint8Arrays(a, b) {
  if (!a.length) {
    a = [a];
  }
  if (!b.length) {
    b = [b];
  }

  const c = new Uint8Array(a.length + b.length);

  c.set(a);
  c.set(b, a.length);

  return c;
}

export function ss58Encode(a: any, type = DEFAULT_TYPE, checksumLength = null, length = null, accountId: any = null) {
  let payload
  if (KNOWN_TYPES.indexOf(type) === -1) {
    throw new Error('Unknown ss58 address type', type)
  }
  if (typeof a === 'number' || a instanceof AccountIndex) {
    let minLength = (a < (1 << 8) ? 1 : a < (1 << 16) ? 2 : a < (1 << 32) ? 4 : 8)
    length = length ? length : minLength
    if ([1, 2, 4, 8].indexOf(length) === -1) {
      throw new Error('Invalid length')
    }
    length = Math.max(minLength, length)
    if (checksumLength && typeof checksumLength !== 'number') {
      throw new Error('Invalid checksum length')
    }
    switch (length) {
      case 1: { checksumLength = 1; break; }
      case 2: { checksumLength = ([1, 2].indexOf(checksumLength) + 1) || 1; break; }
      case 4: { checksumLength = ([1, 2, 3, 4].indexOf(checksumLength) + 1) || 1; break; }
      case 8: { checksumLength = ([1, 2, 3, 4, 5, 6, 7, 8].indexOf(checksumLength) + 1) || 1; break; }
    }
    payload = toLE(a, length)
  } else if ((a instanceof Uint8Array) && ((a.length === 32) || (a.length === 35))) {
    checksumLength = 2
    payload = (a.length === 35) ? a.slice(1, 33) : a
    accountId = payload
  } else {
    throw new Error('Unknown item to encode as ss58. Passing back.', a)
  }
  let hash = blake2b(concatBytes(PREFIX, ((type & 1) ? accountId : mergeUint8Arrays(type, payload))));
  let complete = mergeUint8Arrays(mergeUint8Arrays(type, payload), hash.slice(0, checksumLength));
  return bs58.encode(Buffer.from(complete))
}
/* tslint:enable:no-bitwise */

export function ss58Decode(ss58, lookupIndex=0) {
  let a
  try {
    a = bs58.decode(ss58)
  }
  catch (e) {
    return null
  }

  let type = a[0]
  if (KNOWN_TYPES.indexOf(type) === -1) {
    return null
  }

  if (a.length < 3) {
    return null
    //throw new Error('Invalid length of payload for address', a.length)
  }
  let length = a.length <= 3
    ? 1
    : a.length <= 5
      ? 2
      : a.length <= 9
        ? 4
        : a.length <= 17
          ? 8
          : 32
  let checksumLength = a.length - 1 - length

  let payload = a.slice(1, 1 + length)
  let checksum = a.slice(1 + a.length)

  let accountId
  if (length === 32) {
    accountId = payload
  }

  let result = length < 32
    ? new AccountIndex(leToNumber(payload))
    : new Buffer.from(payload)

  if (a[0] % 1 && !accountId && !lookupIndex) {
    return null
  }
  let hash = blake2b(concatBytes(PREFIX, (a[0] % 1 ? (accountId || lookupIndex(result)) : a.slice(0, 1 + length))))

  for (var i = 0; i < checksumLength; ++i) {
    if (hash[i] !== a[1 + length + i]) {
      // invalid checksum
      return null
    }
  }

  return result
}
