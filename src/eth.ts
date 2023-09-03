import { type BytesCoder } from "@scure/base";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import { Keccak } from "sha3";

export const SLIP44_MSB = 0x80000000;

export class EthereumChainIdError extends Error {}

/**
 * @throws EthereumChainIdError
 */
export function ethChainIdToCoinType(chainId: number): number {
  if (chainId >= SLIP44_MSB) {
    throw new EthereumChainIdError(`chainId ${chainId} must be less than ${SLIP44_MSB}`);
  }
  return (SLIP44_MSB | chainId) >>> 0;
}

/**
 * @throws EthereumChainIdError
 */
export function coinTypeToEthChainId(coinType: number): number {
  if ((coinType & SLIP44_MSB) === 0) {
    throw new EthereumChainIdError(`coinType ${coinType} is not an EVM chain`);
  }
  return ((SLIP44_MSB - 1) & coinType) >> 0;
}

export function makeChecksummedHexCoder(chainId?: string): BytesCoder {
  return {
    encode(data: Uint8Array): string {
      return toChecksumAddress(bytesToHex(data), chainId);
    },
    decode(data: string): Uint8Array {
      const stripped = data.replace(/^0x/, "");
      if (
        !isValidChecksumAddress(data, chainId) &&
        stripped !== stripped.toLowerCase() &&
        stripped !== stripped.toUpperCase()
      ) {
        throw Error("Invalid address checksum");
      }
      return hexToBytes(stripped);
    },
  };
}

function keccak(a: string) {
  return new Keccak(256).update(a).digest();
}

const toChecksumAddress = (address: string, chainId?: string) => {
  if (typeof address !== "string") {
    throw new Error("stripHexPrefix param must be type 'string', is currently type " + typeof address + ".");
  }
  const strip_address = stripHexPrefix(address).toLowerCase();
  const prefix = chainId != null ? chainId.toString() + "0x" : "";
  const keccak_hash = keccak(prefix + strip_address).toString("hex");
  let output = "0x";

  for (let i = 0; i < strip_address.length; i++)
    output += parseInt(keccak_hash[i], 16) >= 8 ? strip_address[i].toUpperCase() : strip_address[i];
  return output;
};

function isValidChecksumAddress(address: string, chainId?: string) {
  return isValidAddress(address) && toChecksumAddress(address, chainId) === address;
}

function isValidAddress(address: string) {
  return /^0x[0-9a-fA-F]{40}$/.test(address);
}
export const stripHexPrefix = (str: string) => {
  return str.slice(0, 2) === "0x" ? str.slice(2) : str;
};
