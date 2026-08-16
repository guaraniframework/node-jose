import { DigitalSignatureAlgorithm } from '../../../jwa/jws/digital-signature-algorithm.type';
import { JsonWebKey } from '../../../jwk/jsonwebkey';

/**
 * Signed JSON Web Token deserialization options.
 */
export interface SignedJsonWebTokenDeserializationOptions {
  /**
   * JSON Web Key.
   */
  readonly jsonWebKey?: JsonWebKey | null;

  /**
   * Expected JSON Web Signature Digital Signature Algorithms.
   */
  readonly expectedDigitalSignatureAlgorithms?: DigitalSignatureAlgorithm[];
}
