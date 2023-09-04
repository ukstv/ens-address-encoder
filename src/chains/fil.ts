import { blake2b } from "@noble/hashes/blake2b";
import { UnrecognizedAddressFormatError } from "../format.js";
import { base32unpadded, equalBytes } from "./numbers-bytes.js";
import { BytesCoder, Coder, utils } from "@scure/base";
import { concatBytes } from "@noble/hashes/utils";

const NETWORKS = ["t", "f"];

function isChecksumCorrect(ingest: Uint8Array, expect: Uint8Array): boolean {
  const digest = getChecksum(ingest);
  return equalBytes(digest, expect);
}

function getChecksum(ingest: Uint8Array): Uint8Array {
  return blake2b(ingest, { dkLen: 4 });
}

function checkAddressString(address: string) {
  if (address.length < 3) {
    // Address is too short to validate
    throw new UnrecognizedAddressFormatError();
  }
  if (!NETWORKS.includes(address[0])) {
    // Unknown address network
    throw new UnrecognizedAddressFormatError();
  }

  switch (address[1]) {
    case "0": {
      if (address.length > 22) {
        // Invalid ID address length
        throw new UnrecognizedAddressFormatError();
      }
      break;
    }
    case "1": {
      if (address.length !== 41) {
        // Invalid secp256k1 address length
        throw new UnrecognizedAddressFormatError();
      }
      break;
    }
    case "2": {
      if (address.length !== 41) {
        // Invalid Actor address length
        throw new UnrecognizedAddressFormatError();
      }
      break;
    }
    case "3": {
      if (address.length !== 86) {
        // Invalid BLS address length
        throw new UnrecognizedAddressFormatError();
      }
      break;
    }
    default: {
      // Invalid address protocol
      throw new UnrecognizedAddressFormatError();
    }
  }
}

function filDecode(address: string): Uint8Array {
  checkAddressString(address);
  const network = address[0];
  const protocol = parseInt(address[1], 10);
  const protocolByte = Uint8Array.from([protocol]);
  const raw = address.slice(2);

  if (protocol === 0) {
    return concatBytes(protocolByte, LEBCoder.encode(BigInt(raw)));
  }

  const payloadChecksum = base32unpadded.decode(raw.toUpperCase());
  const length = payloadChecksum.length;
  const payload = payloadChecksum.slice(0, length - 4);
  const checksum = payloadChecksum.slice(length - 4, length);
  if (!isChecksumCorrect(concatBytes(protocolByte, payload), checksum)) {
    throw new UnrecognizedAddressFormatError();
  }

  const addressObj = new Address(concatBytes(protocolByte, payload));
  if (filEncode(network, addressObj) !== address) {
    throw Error(`Did not encode this address properly: ${address}`);
  }
  return concatBytes(protocolByte, payload);
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
      const decoded = LEBCoder.decode(payload);
      addressString = network + String(protocol) + String(decoded);
      break;
    }
    default: {
      const protocolByte = Uint8Array.from([protocol]);
      const toChecksum = concatBytes(protocolByte, payload);
      const checksum = getChecksum(toChecksum);
      const bytes = concatBytes(payload, Uint8Array.from(checksum));
      const bytes32encoded = base32unpadded.encode(bytes).toLowerCase();
      addressString = String(network) + String(protocol) + bytes32encoded;
      break;
    }
  }
  return addressString;
}

export const filCoder: BytesCoder = {
  encode(data: Uint8Array): string {
    const address = new Address(data);
    return filEncode("f", address).toString();
  },
  decode(data: string): Uint8Array {
    return filDecode(data);
  },
};

class Address {
  public str: Uint8Array;
  constructor(str: Uint8Array) {
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

  public payload(): Uint8Array {
    if (this.str.length < 1) {
      throw Error("No address found.");
    }
    return this.str.slice(1, this.str.length);
  }
}

// LEB128
const LEBCoder: Coder<bigint, Uint8Array> = {
  encode(value: bigint): Uint8Array {
    const bytes: number[] = [];
    do {
      let byte = Number(value & 127n); // low-order 7 bits of value
      value >>= 7n;
      if (value != 0n) {
        //   set high-order bit of byte;
        byte = byte | 128;
      }
      bytes.push(byte);
    } while (value != 0n);
    return Uint8Array.from(bytes);
  },
  decode(buffer: Uint8Array): bigint {
    let result = 0n;
    let shift = 0n;
    for (const byte of buffer) {
      result |= BigInt(byte & 127) << shift;
      if ((byte & 128) === 0) {
        break;
      }
      shift += 7n;
    }
    return result;
  },
};
