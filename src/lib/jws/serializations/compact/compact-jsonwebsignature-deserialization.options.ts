import { Buffer } from 'buffer';

import { DigitalSignatureAlgorithm } from '../../../jwa/jws/digital-signature-algorithm.type';
import { JsonWebKey } from '../../../jwk/jsonwebkey';

/**
 * Compact JSON Web Signature deserialization options.
 */
export interface CompactJsonWebSignatureDeserializationOptions {
  /**
   * JSON Web Key.
   */
  readonly jwk?: JsonWebKey | null;

  /**
   * Expected JSON Web Signature Digital Signature Algorithms.
   */
  readonly expectedDigitalSignatureAlgorithms?: DigitalSignatureAlgorithm[];

  /**
   * Detached Payload.
   */
  readonly detachedPayload?: Buffer;
}
