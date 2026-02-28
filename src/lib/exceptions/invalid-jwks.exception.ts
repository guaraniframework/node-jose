import { JoseException } from './jose.exception';

/**
 * Raised when the provided JWK Set is invalid.
 */
export class InvalidJwksException extends JoseException {
  /**
   * Instantiates a new Invalid JWK Set Exception.
   *
   * @param message Error Message.
   */
  public constructor(message = 'The provided JWK Set is invalid.', options?: ErrorOptions) {
    super(message, options);
  }
}
