import { blake2b } from "@noble/hashes/blake2b";
import { utils, BytesCoder, Coder } from "@scure/base";

const NANO_ALPHABET = "13456789abcdefghijkmnopqrstuwxyz";
const nanoRadix: Coder<Uint8Array, number[]> = {
  encode: (bytes) => nanoRadixConvert(bytes, 8, 5),
  decode: (digits) => {
    const length = digits.length;
    const leftover = (length * 5) % 8;
    let result = nanoRadixConvert(digits, 5, 8);
    if (leftover !== 0) {
      result = result.slice(1);
    }
    return Uint8Array.from(result);
  },
};

const NANO_BASE_32 = utils.chain(nanoRadix, utils.alphabet(NANO_ALPHABET), utils.join(""));

export const nanoCoder: BytesCoder = {
  encode(data: Uint8Array): string {
    const encoded = NANO_BASE_32.encode(data);
    const checksum = blake2b(data, { dkLen: 5 }).reverse();
    const checksumEncoded = NANO_BASE_32.encode(checksum);
    return `nano_${encoded}${checksumEncoded}`;
  },
  decode(data: string): Uint8Array {
    const decoded = NANO_BASE_32.decode(data.substring(5));
    return decoded.subarray(0, -5);
  },
};

function nanoRadixConvert(data: ArrayLike<number>, from: number, to: number) {
  const length = data.length;
  const leftover = (length * from) % to;
  const offset = leftover === 0 ? 0 : to - leftover;

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
