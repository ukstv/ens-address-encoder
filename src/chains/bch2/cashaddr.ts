/**
 * @license
 * https://reviews.bitcoinabc.org
 * Copyright (c) 2017-2020 Emilio Almansi
 * Copyright (c) 2023 Bitcoin ABC
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or http://www.opensource.org/licenses/mit-license.php.
 */

import * as scureBase from "@scure/base";
import bigInt from "big-integer";
import bs58check from "bs58check";
import { convertBits } from "./convertBits.js";
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
function encode(prefix: string, type: string, hash: string | Uint8Array): string {
  validate(typeof prefix === "string" && isValidPrefix(prefix), "Invalid prefix: " + prefix + ".");
  validate(typeof type === "string", "Invalid type: " + type + ".");
  validate(
    hash instanceof Uint8Array || typeof hash === "string",
    "Invalid hash: " + hash + ". Must be string or Uint8Array.",
  );
  if (typeof hash === "string") {
    hash = stringToUint8Array(hash);
  }
  var prefixData = concatBytes(prefixToUint5Array(prefix), new Uint8Array(1));
  var versionByte = getTypeBits(type.toUpperCase()) + getHashSizeBits(hash);
  var payloadData = toUint5Array(concatBytes(new Uint8Array([versionByte]), hash));
  var checksumData = concatBytes(prefixData, payloadData, new Uint8Array(8));
  var payload = concatBytes(payloadData, checksumToUint5Array(polymod(checksumData)));
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
  return hasSingleCase(prefix) && VALID_PREFIXES.indexOf(prefix.toLowerCase()) !== -1;
}

/**
 * Derives an array from the given prefix to be used in the computation
 * of the address' checksum.
 *
 * @private
 * @param {string} prefix Cash address prefix. E.g.: 'ecash'.
 * @returns {Uint8Array}
 */
function prefixToUint5Array(prefix: string): Uint8Array {
  var result = new Uint8Array(prefix.length);
  for (var i = 0; i < prefix.length; ++i) {
    result[i] = prefix[i].charCodeAt(0) & 31;
  }
  return result;
}

/**
 * Returns an array representation of the given checksum to be encoded
 * within the address' payload.
 *
 * @private
 * @param {BigInteger} checksum Computed checksum.
 * @returns {Uint8Array}
 */
function checksumToUint5Array(checksum: bigInt.BigInteger): Uint8Array {
  var result = new Uint8Array(8);
  for (var i = 0; i < 8; ++i) {
    result[7 - i] = checksum.and(31).toJSNumber();
    checksum = checksum.shiftRight(5);
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

/**
 * Returns the bit representation of the length in bits of the given
 * hash within the version byte.
 *
 * @private
 * @param {Uint8Array} hash Hash to encode represented as an array of 8-bit integers.
 * @returns {number}
 * @throws {ValidationError}
 */
function getHashSizeBits(hash: Uint8Array): number {
  switch (hash.length * 8) {
    case 160:
      return 0;
    case 192:
      return 1;
    case 224:
      return 2;
    case 256:
      return 3;
    case 320:
      return 4;
    case 384:
      return 5;
    case 448:
      return 6;
    case 512:
      return 7;
    default:
      throw new ValidationError("Invalid hash size: " + hash.length + ".");
  }
}

/**
 * Converts an array of 8-bit integers into an array of 5-bit integers,
 * right-padding with zeroes if necessary.
 *
 * @private
 * @param {Uint8Array} data
 * @returns {Uint8Array}
 */
function toUint5Array(data: Uint8Array): Uint8Array {
  return convertBits(data, 8, 5);
}

function polymod(data: ArrayLike<number>): bigInt.BigInteger {
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
  return bigInt(checksum ^ 1n);
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
  return polymod(checksumData).equals(0);
}

/**
 * Returns true if, and only if, the given string contains either uppercase
 * or lowercase letters, but not both.
 *
 * @private
 * @param {string} string Input string.
 * @returns {boolean}
 */
function hasSingleCase(string: string): boolean {
  return string === string.toLowerCase() || string === string.toUpperCase();
}

/**
 * Returns a uint8array for a given string input
 *
 * @private
 * @param {string} string Input string.
 * @returns {Uint8Array}
 */
function stringToUint8Array(string: string): Uint8Array {
  const buffer = Buffer.from(string, "hex");
  const arrayBuffer = new ArrayBuffer(buffer.length);
  const uint8Array = new Uint8Array(arrayBuffer);
  for (let i = 0; i < uint8Array.length; i += 1) {
    uint8Array[i] = buffer[i];
  }
  return uint8Array;
}

/**
 * Returns a uint8array for a given string input
 *
 * @private
 * @param {Uint8Array} uint8Array Input string.
 * @returns {string}
 */
function uint8arraytoString(uint8Array: Uint8Array): string {
  let buffer = [];
  for (let i = 0; i < uint8Array.length; i += 1) {
    buffer.push(uint8Array[i]);
  }
  // @ts-expect-error
  const hexBuffer = Buffer.from(buffer, "hex");
  const string = hexBuffer.toString("hex");
  return string;
}

/**
 * Get type and hash from an outputScript
 *
 * Supported outputScripts:
 *
 * P2PKH: 76a914<hash>88ac
 * P2SH:  a914<hash>87
 *
 * Validates for supported outputScript and hash length *
 *
 * @private
 * @param {string} outputScript an ecash tx outputScript
 * @returns {object}
 * @throws {ValidationError}
 */
function getTypeAndHashFromOutputScript(outputScript: string) {
  const p2pkhPrefix = "76a914";
  const p2pkhSuffix = "88ac";

  const p2shPrefix = "a914";
  const p2shSuffix = "87";

  let hash, type;

  // If outputScript begins with '76a914' and ends with '88ac'
  if (
    outputScript.slice(0, p2pkhPrefix.length) === p2pkhPrefix &&
    outputScript.slice(-1 * p2pkhSuffix.length) === p2pkhSuffix
  ) {
    // We have type p2pkh
    type = "p2pkh";

    // hash is the string in between '76a194' and '88ac'
    hash = outputScript.substring(
      outputScript.indexOf(p2pkhPrefix) + p2pkhPrefix.length,
      outputScript.lastIndexOf(p2pkhSuffix),
    );
    // If outputScript begins with 'a914' and ends with '87'
  } else if (
    outputScript.slice(0, p2shPrefix.length) === p2shPrefix &&
    outputScript.slice(-1 * p2shSuffix.length) === p2shSuffix
  ) {
    // We have type p2sh
    type = "p2sh";
    // hash is the string in between 'a914' and '87'
    hash = outputScript.substring(
      outputScript.indexOf(p2shPrefix) + p2shPrefix.length,
      outputScript.lastIndexOf(p2shSuffix),
    );
  } else {
    // Throw validation error if outputScript not of these two types
    throw new ValidationError("Unsupported outputScript: " + outputScript);
  }

  // Throw validation error if hash is of invalid size
  // Per spec, valid hash sizes in bytes
  const VALID_SIZES = [20, 24, 28, 32, 40, 48, 56, 64];

  if (!VALID_SIZES.includes(hash.length / 2)) {
    throw new ValidationError("Invalid hash size in outputScript: " + outputScript);
  }
  return { type, hash };
}

/**
 * Encodes a given outputScript into an eCash address using the optionally specified prefix.
 *
 * @static
 * @param {string} outputScript an ecash tx outputScript
 * @param {string} prefix Cash address prefix. E.g.: 'ecash'.
 * @returns {string}
 * @throws {ValidationError}
 */
function encodeOutputScript(outputScript: string, prefix = "ecash"): string {
  // Get type and hash from outputScript
  const { type, hash } = getTypeAndHashFromOutputScript(outputScript);

  // The encode function validates hash for correct length
  return encode(prefix, type, hash);
}

/**
 * Converts an ecash address to legacy format
 *
 * @static
 * @param {string} cashaddress a valid p2pkh or p2sh ecash address
 * @returns {string}
 * @throws {ValidationError}
 */
function toLegacy(cashaddress: string): string {
  const { prefix, type, hash } = decode(cashaddress);
  // @ts-expect-error
  const isMainnet = VALID_PREFIXES_MAINNET.includes(prefix);
  // Get correct version byte for legacy format
  let versionByte;
  switch (type) {
    case "P2PKH":
      versionByte = isMainnet ? 0 : 111;
      break;
    case "P2SH":
      versionByte = isMainnet ? 5 : 196;
      break;
    default:
      throw new ValidationError("Unsupported address type: " + type);
  }
  var buffer = Buffer.alloc(1 + hash.length);
  buffer[0] = versionByte;
  // @ts-expect-error
  buffer.set(hash, 1);
  return bs58check.encode(buffer);
}

/**
 * Return true for a valid cashaddress
 * Prefixless addresses with valid checksum are also valid
 *
 * @static
 * @param {string} testedAddress a string tested for cashaddress validity
 * @param {string} optionalPrefix cashaddr prefix
 * @returns {bool}
 * @throws {ValidationError}
 */
function isValidCashAddress(cashaddress: string, optionalPrefix = false) {
  try {
    const { prefix } = decode(cashaddress);
    if (optionalPrefix) {
      // @ts-expect-error
      return prefix === optionalPrefix;
    }
    return true;
  } catch (err) {
    return false;
  }
}

/**
 * Return true for a valid cashaddress
 * Prefixless addresses with valid checksum are also valid
 *
 * @static
 * @param {string} address a valid p2pkh or p2sh cash address
 * @returns {string} the outputScript associated with this address and type
 * @throws {ValidationError} if decode fails
 */
function getOutputScriptFromAddress(address: string) {
  const { type, hash } = decode(address, true);
  let registrationOutputScript;
  if (type === "p2pkh") {
    registrationOutputScript = `76a914${hash}88ac`;
  } else {
    registrationOutputScript = `a914${hash}87`;
  }
  return registrationOutputScript;
}

export {
  encode,
  decode,
  uint8arraytoString,
  encodeOutputScript,
  getTypeAndHashFromOutputScript,
  toLegacy,
  isValidCashAddress,
  getOutputScriptFromAddress,
  ValidationError,
};
