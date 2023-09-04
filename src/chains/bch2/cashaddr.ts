/**
 * @license
 * https://reviews.bitcoinabc.org
 * Copyright (c) 2017-2020 Emilio Almansi
 * Copyright (c) 2023 Bitcoin ABC
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or http://www.opensource.org/licenses/mit-license.php.
 */

import * as scureBase from "@scure/base";
import { validate, ValidationError } from "./validation.js";
import { UnrecognizedAddressFormatError } from "../../format";
import { concatBytes } from "@noble/hashes/utils";

export enum AddressType {
  P2PKH = "P2PKH",
  P2SH = "P2SH",
}

const BCH_BASE32 = scureBase.utils.chain(
  scureBase.utils.alphabet("qpzry9x8gf2tvdw0s3jn54khce6mua7l"),
  scureBase.utils.join(""),
);
const RADIX5 = scureBase.utils.radix2(5);
const HASH_SIZE: Record<number, number> = {
  0: 160,
  1: 192,
  2: 224,
  3: 256,
  4: 320,
  5: 384,
  6: 448,
  7: 512,
};
const HASH_SIZE_BITS: Record<number, number> = Object.fromEntries(
  Object.entries(HASH_SIZE).map(([k, v]) => {
    return [v, Number(k)];
  }),
);

/**
 * Encodes a hash from a given type into an eCash address with the given prefix.
 *
 * @static
 * @param {string} prefix Cash address prefix. E.g.: 'ecash'.
 * @param {string} type Type of address to generate. Either 'P2PKH' or 'P2SH'. Case-insensitive.
 * @param {Uint8Array or string} hash Hash to encode represented as an array of 8-bit integers.
 * @returns {string}
 * @throws {ValidationError}
 */
function encode(prefix: string, type: string, hash: Uint8Array): string {
  validate(isValidPrefix(prefix), "Invalid prefix: " + prefix + ".");
  const prefixData = concatBytes(prefixToUint5Array(prefix), new Uint8Array(1));
  const versionByte = getTypeBits(type.toUpperCase()) + HASH_SIZE_BITS[hash.length * 8];
  const payloadData = new Uint8Array(RADIX5.encode(concatBytes(new Uint8Array([versionByte]), hash)));
  const checksumData = concatBytes(prefixData, payloadData, new Uint8Array(8));
  const payload = concatBytes(payloadData, checksumToUint5Array(polymod(checksumData)));
  return prefix + ":" + BCH_BASE32.encode(Array.from(payload));
}

/**
 * Decodes the given address into its constituting prefix, type and hash. See [#encode()]{@link encode}.
 *
 * @static
 * @param {string} address Address to decode. E.g.: 'ecash:qpm2qsznhks23z7629mms6s4cwef74vcwva87rkuu2'.
 * @param {returnHashAsString} bool User may ask for the hash160 be returned as a string instead of a uint8array
 * @returns {object}
 * @throws {ValidationError}
 */
function decode(address: string): { prefix?: string; type?: string; hash: string | Uint8Array } {
  if (!hasSingleCase(address)) throw new UnrecognizedAddressFormatError();
  const pieces = address.toLowerCase().split(":");
  // if there is no prefix, it might still be valid
  let prefix, payload;
  if (pieces.length === 1) {
    // Check and see if it has a valid checksum for accepted prefixes
    let hasValidChecksum = false;
    for (let i = 0; i < VALID_PREFIXES.length; i += 1) {
      const testedPrefix = VALID_PREFIXES[i];
      const prefixlessPayload = new Uint8Array(BCH_BASE32.decode(pieces[0]));
      hasValidChecksum = validChecksum(testedPrefix, prefixlessPayload);
      if (hasValidChecksum) {
        // Here's your prefix
        prefix = testedPrefix;
        payload = prefixlessPayload;
        // Stop testing other prefixes
        break;
      }
    }
    if (!hasValidChecksum) throw new UnrecognizedAddressFormatError();
    if (!payload) throw new Error(`Something went wrong`);
    var payloadData = RADIX5.decode(Array.from(payload.subarray(0, -8)));
    var versionByte = payloadData[0];
    var hash = payloadData.subarray(1);
    validate(HASH_SIZE[versionByte & 7] === hash.length * 8, "Invalid hash size: " + address + ".");
    const type = getType(versionByte);
    return {
      prefix: prefix,
      type: type,
      hash: hash,
    };
  } else {
    if (pieces.length !== 2) throw new UnrecognizedAddressFormatError();
    prefix = pieces[0];
    payload = new Uint8Array(BCH_BASE32.decode(pieces[1]));
    if (!validChecksum(prefix, payload)) throw new UnrecognizedAddressFormatError();
    var payloadData = RADIX5.decode(Array.from(payload.subarray(0, -8)));
    var versionByte = payloadData[0];
    var hash = payloadData.subarray(1);
    validate(HASH_SIZE[versionByte & 7] === hash.length * 8, "Invalid hash size: " + address + ".");
    const type = getType(versionByte);
    return {
      prefix: prefix,
      type: type,
      hash: hash,
    };
  }
  throw new UnrecognizedAddressFormatError();
}

/**
 * All valid address prefixes.
 *
 * @private
 */
var VALID_PREFIXES = ["ecash", "bitcoincash", "simpleledger", "etoken", "ectest", "ecregtest", "bchtest", "bchreg"];

/**
 * Valid mainnet prefixes
 *
 * @private
 */
var VALID_PREFIXES_MAINNET = ["ecash", "bitcoincash", "simpleledger", "etoken"];

/**
 * Checks whether a string is a valid prefix; ie., it has a single letter case
 * and is one of 'ecash', 'ectest', 'etoken', etc
 *
 * @private
 * @param {string} prefix
 * @returns {boolean}
 */
function isValidPrefix(prefix: string): boolean {
  return hasSingleCase(prefix) && VALID_PREFIXES.includes(prefix.toLowerCase());
}

function prefixToUint5Array(prefix: string): Uint8Array {
  const result = new Uint8Array(prefix.length);
  for (let i = 0; i < prefix.length; i++) {
    result[i] = prefix[i].charCodeAt(0) & 31;
  }
  return result;
}

function checksumToUint5Array(checksum: bigint): Uint8Array {
  const result = new Uint8Array(8);
  for (let i = 0; i < 8; i++) {
    result[7 - i] = Number(checksum & 31n);
    checksum = checksum >> 5n;
  }
  return result;
}

/**
 * Returns the bit representation of the given type within the version
 * byte.
 *
 * @private
 * @param {string} type Address type. Either 'P2PKH' or 'P2SH'.
 * @returns {number}
 * @throws {ValidationError}
 */
function getTypeBits(type: string) {
  switch (type) {
    case "p2pkh":
    case "P2PKH":
      return 0;
    case "p2sh":
    case "P2SH":
      return 8;
    default:
      throw new ValidationError("Invalid type: " + type + ".");
  }
}

function getType(versionByte: number): AddressType {
  switch (versionByte & 120) {
    case 0:
      return AddressType.P2PKH;
    case 8:
      return AddressType.P2SH;
    default:
      throw new UnrecognizedAddressFormatError();
  }
}

function polymod(data: ArrayLike<number>): bigint {
  const GENERATOR = [0x98f2bc8e61n, 0x79b76d99e2n, 0xf33e5fb3c4n, 0xae2eabe2a8n, 0x1e4f43e470n];
  let checksum = 1n;
  for (var i = 0; i < data.length; ++i) {
    const value = data[i];
    const topBits = checksum >> 35n;
    checksum = ((checksum & 0x07ffffffffn) << 5n) ^ BigInt(value);
    for (var j = 0; j < GENERATOR.length; ++j) {
      if (((topBits >> BigInt(j)) & 1n) === 1n) {
        checksum = checksum ^ GENERATOR[j];
      }
    }
  }
  return checksum ^ 1n;
}

/**
 * Verify that the payload has not been corrupted by checking that the
 * checksum is valid.
 *
 * @private
 * @param {string} prefix Cash address prefix. E.g.: 'ecash'.
 * @param {Uint8Array} payload Array of 5-bit integers containing the address' payload.
 * @returns {boolean}
 */
function validChecksum(prefix: string, payload: Uint8Array): boolean {
  var prefixData = concatBytes(prefixToUint5Array(prefix), new Uint8Array(1));
  var checksumData = concatBytes(prefixData, payload);
  return polymod(checksumData) === 0n;
}

function hasSingleCase(string: string): boolean {
  return string === string.toLowerCase() || string === string.toUpperCase();
}

export { encode, decode };
