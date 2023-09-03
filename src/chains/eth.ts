import { type BytesCoder } from "@scure/base";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import { keccak_256 } from "@noble/hashes/sha3";

export const SLIP44_MSB = 0x80000000;

export class EthereumChainIdError extends Error {}
export class InvalidAddressChecksumError extends Error {
  constructor() {
    super("Invalid address checksum");
  }
}

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

function stripHexPrefix(str: string): string {
  return str.replace(/^0x/, "");
}

function isValidAddress(address: string): boolean {
  return /^0x[0-9a-fA-F]{40}$/.test(address);
}

function isValidChecksumAddress(address: string, chainId?: number): boolean {
  return isValidAddress(address) && toChecksumAddress(address, chainId) === address;
}

export function makeChecksummedHexCoder(chainId?: number): BytesCoder {
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
        throw new InvalidAddressChecksumError();
      }
      return hexToBytes(stripped);
    },
  };
}

function toChecksumAddress(address: string, chainId?: number) {
  const stripped = stripHexPrefix(address).toLowerCase();
  const prefix = chainId ? String(chainId) + "0x" : "";
  const hashHex = bytesToHex(keccak_256(prefix + stripped));

  let output = "0x";
  for (let i = 0; i < stripped.length; i++) {
    const gt8 = parseInt(hashHex[i], 16) >= 8;
    if (gt8) {
      output += stripped[i].toUpperCase();
    } else {
      output += stripped[i];
    }
  }
  return output;
}
