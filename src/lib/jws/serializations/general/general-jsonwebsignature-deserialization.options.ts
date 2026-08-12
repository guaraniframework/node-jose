import { Buffer } from 'buffer';

import { GeneralJsonWebSignatureDeserializationOptionsSignature } from './general-jsonwebsignature-deserialization-options-signature';

/**
 * General JSON Web Signature deserialization options.
 */
export interface GeneralJsonWebSignatureDeserializationOptions {
  /**
   * Detached Payload.
   */
  readonly detachedPayload?: Buffer;

  /**
   * Signatures options.
   */
  readonly signatures?: GeneralJsonWebSignatureDeserializationOptionsSignature[];
}
