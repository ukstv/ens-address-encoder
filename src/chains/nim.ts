import { BytesCoder, utils } from "@scure/base";
import { UnrecognizedAddressFormatError } from "../format.js";

const CCODE = "NQ";
const BASE32_ALPHABET_NIMIQ = "0123456789ABCDEFGHJKLMNPQRSTUVXY";
const NIM_BASE32 = utils.chain(
  utils.radix2(5),
  utils.alphabet(BASE32_ALPHABET_NIMIQ),
  utils.padding(5),
  utils.join(""),
);

function ibanCheck(data: string): number {
  const num = data
    .toUpperCase()
    .split("")
    .map((c) => {
      const code = c.charCodeAt(0);
      if (code >= 48 && code <= 57) {
        return c; // number
      } else {
        return (code - 55).toString();
      }
    })
    .join("");

  let tmp = "";
  for (let i = 0; i < Math.ceil(num.length / 6); i++) {
    const a = num.slice(i * 6, i * 6 + 6);
    tmp = (parseInt(tmp + a, 10) % 97).toString();
  }

  return parseInt(tmp, 10);
}

function nimqCheck(str: string, ccode: string): string {
  return ("00" + (98 - ibanCheck(str + ccode + "00"))).slice(-2);
}

export const nimCoder: BytesCoder = {
  encode(data: Uint8Array) {
    const base32Part = NIM_BASE32.encode(Buffer.from(data));
    const check = nimqCheck(base32Part, CCODE);
    return (CCODE + check + base32Part).replace(/.{4}/g, "$& ").trim();
  },
  decode(data: string): Uint8Array {
    if (!data.startsWith(CCODE)) {
      throw new UnrecognizedAddressFormatError();
    }
    const addr = data.replace(/ /g, "");
    const check = addr.slice(2, 4);
    const base32Part = addr.slice(4);

    if (check !== nimqCheck(base32Part, CCODE)) {
      throw new UnrecognizedAddressFormatError();
    }

    return NIM_BASE32.decode(base32Part);
  },
};
