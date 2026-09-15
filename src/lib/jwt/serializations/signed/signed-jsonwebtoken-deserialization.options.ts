import { DigitalSignatureAlgorithm } from '../../../jwa/jws/digital-signature-algorithm.type';
import { JsonWebKey } from '../../../jwk/jsonwebkey';
import { JsonWebTokenClaimsOptions } from '../../jsonwebtoken-claims.options';

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

  /**
   * JSON Web Token Claims Options.
   */
  readonly claimsOptions?: JsonWebTokenClaimsOptions;
}
