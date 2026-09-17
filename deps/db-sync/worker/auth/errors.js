"use strict";

/**
 * Error raised for any request the auth service refuses. `code` is a stable
 * machine-readable identifier returned to the client, `status` the HTTP status.
 */
class AuthError extends Error {
  constructor(code, message, status = 400) {
    super(message);
    this.name = "AuthError";
    this.code = code;
    this.status = status;
  }
}

module.exports = { AuthError };
