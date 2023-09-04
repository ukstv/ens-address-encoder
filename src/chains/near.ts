import { BytesCoder, utf8 } from "@scure/base";

export const nearCoder: BytesCoder = {
  encode(data: Uint8Array): string {
    const ndata = utf8.encode(data);
    if (ndata.length > 64 || ndata.length < 2) {
      throw Error("Invalid address format");
    }
    return ndata;
  },
  decode(data: string): Uint8Array {
    const regex = /(^(([a-z\d]+[\-_])*[a-z\d]+\.)*([a-z\d]+[\-_])*[a-z\d]+$)/g;
    if (!regex.test(data)) {
      throw Error("Invalid address string");
    } else {
      if (data.length > 64 || data.length < 2) {
        throw Error("Invalid address format");
      }
      return utf8.decode(data);
    }
  },
};
