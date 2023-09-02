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
