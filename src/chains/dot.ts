import { blake2b } from "@noble/hashes/blake2b";
import { concatBytes, utf8ToBytes } from "@noble/hashes/utils";
import { base58 } from "@scure/base";
import { UnrecognizedAddressFormatError } from "../format.js";

export function dotAddrEncoder(data: Uint8Array): string {
  return ss58Encode(data, 0);
}

export function ksmAddrDecoder(data: string): Uint8Array {
  return ss58Decode(data);
}

const DEFAULT_TYPE = 42;
const KNOWN_TYPES = [0, 1, 2, 42, 43, 68, 69];
const PREFIX = utf8ToBytes("SS58PRE");

class AccountIndex extends Number {
  toJSON() {
    return { _type: "AccountIndex", data: this + 0 };
  }
}

function leToNumber(le) {
  let r = 0;
  let a = 1;
  le.forEach((x) => {
    r += x * a;
    a *= 256;
  });
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

export function ss58Encode(
  a: Uint8Array,
  type = DEFAULT_TYPE,
  checksumLength = null,
  length = null,
  accountId: any = null,
) {
  let payload;
  if (!KNOWN_TYPES.includes(type)) {
    throw new UnrecognizedAddressFormatError();
  }
  if (a.length === 32 || a.length === 35) {
    checksumLength = 2;
    payload = a.length === 35 ? a.slice(1, 33) : a;
    accountId = payload;
  } else {
    throw new Error("Unknown item to encode as ss58. Passing back.", a);
  }
  let hash = blake2b(concatBytes(PREFIX, type & 1 ? accountId : mergeUint8Arrays(type, payload)));
  let complete = mergeUint8Arrays(mergeUint8Arrays(type, payload), hash.slice(0, checksumLength));
  const r = base58.encode(Uint8Array.from(complete));
  return r;
}
/* tslint:enable:no-bitwise */

export function ss58Decode(ss58: string, lookupIndex = 0) {
  const a = base58.decode(ss58);

  let type = a[0];
  if (KNOWN_TYPES.indexOf(type) === -1) {
    return null;
  }

  if (a.length < 3) {
    return null;
    //throw new Error('Invalid length of payload for address', a.length)
  }
  let length = a.length <= 3 ? 1 : a.length <= 5 ? 2 : a.length <= 9 ? 4 : a.length <= 17 ? 8 : 32;
  let checksumLength = a.length - 1 - length;

  let payload = a.slice(1, 1 + length);

  let accountId;
  if (length === 32) {
    accountId = payload;
  }

  let result = Buffer.from(payload);

  if (a[0] % 1 && !accountId && !lookupIndex) {
    return null;
  }
  let hash = blake2b(concatBytes(PREFIX, a[0] % 1 ? accountId || lookupIndex(result) : a.slice(0, 1 + length)));

  for (var i = 0; i < checksumLength; ++i) {
    if (hash[i] !== a[1 + length + i]) {
      // invalid checksum
      return null;
    }
  }

  return result;
}
