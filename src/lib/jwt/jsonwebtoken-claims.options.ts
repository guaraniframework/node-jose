import { JsonWebTokenClaimValidationOptions } from './jsonwebtoken-claims-validation.options';

/**
 * JSON Web Token Claims Options.
 */
export interface JsonWebTokenClaimsOptions {
  /**
   * Indicates if the value of the JSON Web Token Claim "exp" should be ignored.
   *
   * @default false
   */
  readonly ignoreExpired?: boolean;

  /**
   * Options used to validate the JSON Web Token Claims in a fine-grained manner.
   */
  readonly validationOptions?: Record<string, JsonWebTokenClaimValidationOptions | null>;
}
