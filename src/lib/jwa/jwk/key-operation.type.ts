/**
 * Identifies the operation(s) for which the key is intended to be used.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-4.3|RFC 7517 "key_ops" (Key Operations) Parameter}
 */
export type KeyOperation =
  | 'decrypt'
  | 'deriveBits'
  | 'deriveKey'
  | 'encrypt'
  | 'sign'
  | 'unwrapKey'
  | 'verify'
  | 'wrapKey';
