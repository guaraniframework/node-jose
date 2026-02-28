import { JoseException } from './jose.exception';

/**
 * Raised when the provided JWK is invalid.
 */
export class InvalidJwkException extends JoseException {
  /**
   * Instantiates a new Invalid JWK Exception.
   *
   * @param message Error Message.
   */
  public constructor(message = 'The provided JWK is invalid.', options?: ErrorOptions) {
    super(message, options);
  }
}
