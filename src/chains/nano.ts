import { blake2b as B2 } from "@noble/hashes/blake2b";
import { utils, BytesCoder, Coder } from "@scure/base";

const NANO_ALPHABET = "13456789abcdefghijkmnopqrstuwxyz";
const nanoRadix: Coder<Uint8Array, number[]> = {
  encode: (bytes) => nanoRadixConvert(bytes, 8, 5),
  decode: (digits) => Uint8Array.from(nanoRadixConvert(digits, 5, 8)),
};
const NANO_BASE_32 = utils.chain(nanoRadix, utils.alphabet("13456789abcdefghijkmnopqrstuwxyz"), utils.join(""));

export const nanoCoder: BytesCoder = {
  encode(data: Uint8Array): string {
    const encoded = NANO_BASE_32.encode(data);
    const checksum = B2(data, { dkLen: 5 }).reverse();
    const checksumEncoded = NANO_BASE_32.encode(checksum);
    return `nano_${encoded}${checksumEncoded}`;
  },
  decode(data: string): Uint8Array {
    const decoded = decode(data.substring(5));
    console.log('d.0', decoded, NANO_BASE_32.decode(data.substring(5)))

    return decoded.subarray(0, -5);
  },
};

function nanoRadixConvert(data: ArrayLike<number>, from: number, to: number) {
  const length = data.length;
  const leftover = (length * 8) % 5;
  const offset = leftover === 0 ? 0 : 5 - leftover;

  let carry = 0;
  let pos = 0; // bitwise position in current element
  const mask = 2 ** to - 1;
  const res: number[] = [];

  for (let i = 0; i < data.length; i++) {
    const n = data[i];
    if (n >= 2 ** from) throw new Error(`convertRadix2: invalid data word=${n} from=${from}`);
    carry = (carry << from) | n;
    if (pos + from > 32) throw new Error(`convertRadix2: carry overflow pos=${pos} from=${from}`);
    pos += from;
    for (; pos >= to; pos -= to) {
      res.push((carry >>> (pos + offset - to)) & mask);
    }
  }
  carry = (carry << (to - (pos + offset))) & mask;
  if (pos > 0) res.push(carry >>> 0);
  return res;
}

function readChar(char: string): number {
  var idx = NANO_ALPHABET.indexOf(char);

  if (idx === -1) {
    throw new Error("Invalid character found: " + char);
  }

  return idx;
}

/**
 * Decodes a Nano-implementation Base32 encoded string into a Uint8Array
 * @param {string} input A Nano-Base32 encoded string
 * @returns {Uint8Array}
 */
function decode(input: string): Uint8Array {
  var length = input.length;
  const leftover = (length * 5) % 8;
  const offset = leftover === 0 ? 0 : 8 - leftover;

  var bits = 0;
  var value = 0;

  var index = 0;
  var output = new Uint8Array(Math.ceil((length * 5) / 8));

  for (var i = 0; i < length; i++) {
    value = (value << 5) | readChar(input[i]);
    bits += 5;

    if (bits >= 8) {
      output[index++] = (value >>> (bits + offset - 8)) & 255;
      bits -= 8;
    }
  }
  if (bits > 0) {
    output[index++] = (value << (bits + offset - 8)) & 255;
  }

  if (leftover !== 0) {
    output = output.slice(1);
  }
  return output;
}
