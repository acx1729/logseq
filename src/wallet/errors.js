/** Errors the wallet module raises; `code` is stable for callers and tests. */
export class WalletError extends Error {
  constructor(code, message, extra = {}) {
    super(message);
    this.name = "WalletError";
    this.code = code;
    Object.assign(this, extra);
  }
}

export function errorMessage(error) {
  if (error instanceof Error) return error.message;
  return String(error);
}
