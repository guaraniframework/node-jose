import { JsonWebEncryptionHeaderParameters } from '../../../../jwe/jsonwebencryption-header.parameters';
import { EllipticCurveJsonWebKeyParameters } from '../../../jwk/ec/elliptic-curve-jsonwebkey.parameters';
import { OctetKeyPairJsonWebKeyParameters } from '../../../jwk/okp/octet-key-pair-jsonwebkey.parameters';

/**
 * ECDH-ES JSON Web Encryption Header Parameters.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-4.6.1|RFC 7518 Header Parameters Used for ECDH Key Agreement}
 */
export interface ECDHESJsonWebEncryptionKeyManagementHeaderParameters extends JsonWebEncryptionHeaderParameters {
  /**
   * Ephemeral Public Key.
   *
   * Created by the originator for the use in key agreement algorithms.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-4.6.1.1|RFC 7518 "epk" (Ephemeral Public Key) Header Parameter}
   */
  readonly epk: EllipticCurveJsonWebKeyParameters | OctetKeyPairJsonWebKeyParameters;

  /**
   * Agreement PartyUInfo.
   *
   * Contains information about the producer.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-4.6.1.2|RFC 7518 "apu" (Agreement PartyUInfo) Header Parameter}
   */
  readonly apu?: string;

  /**
   * Agreement PartyVInfo.
   *
   * Contains information about the recipient.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-4.6.1.3|RFC 7518 "apv" (Agreement PartyVInfo) Header Parameter}
   */
  readonly apv?: string;
}
