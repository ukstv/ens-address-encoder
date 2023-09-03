import { base58xrp, utils } from "@scure/base";
import { sha256 } from "@noble/hashes/sha256";

export const xrpCodec = utils.chain(utils.checksum(4, data => sha256(sha256(data))), base58xrp);
