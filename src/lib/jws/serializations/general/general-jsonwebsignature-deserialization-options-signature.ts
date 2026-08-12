import { DigitalSignatureAlgorithm } from '../../../jwa/jws/digital-signature-algorithm.type';
import { JsonWebKey } from '../../../jwk/jsonwebkey';

/**
 * General JSON Web Signature deserialization options Signature.
 */
export interface GeneralJsonWebSignatureDeserializationOptionsSignature {
  /**
   * JSON Web Key.
   */
  readonly jwk?: JsonWebKey | null;

  /**
   * Expected JSON Web Signature Digital Signature Algorithms.
   */
  readonly expectedDigitalSignatureAlgorithms?: DigitalSignatureAlgorithm[];
}
