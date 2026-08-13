import { Buffer } from 'buffer';

import { DigitalSignatureAlgorithm } from '../../../jwa/jws/digital-signature-algorithm.type';
import { JsonWebKey } from '../../../jwk/jsonwebkey';

/**
 * Flattened JSON Web Signature deserialization options.
 */
export interface FlattenedJsonWebSignatureDeserializationOptions {
  /**
   * JSON Web Key.
   */
  readonly jsonWebKey?: JsonWebKey | null;

  /**
   * Expected JSON Web Signature Digital Signature Algorithms.
   */
  readonly expectedDigitalSignatureAlgorithms?: DigitalSignatureAlgorithm[];

  /**
   * Detached Payload.
   */
  readonly detachedPayload?: Buffer;
}
