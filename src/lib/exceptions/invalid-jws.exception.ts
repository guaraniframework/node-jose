import { JoseException } from './jose.exception';

/**
 * Raised when the provided JWS is invalid.
 */
export class InvalidJwsException extends JoseException {
  /**
   * Instantiates a new Invalid JWS Exception.
   *
   * @param message Error Message.
   */
  public constructor(message = 'The provided JWS is invalid.', options?: ErrorOptions) {
    super(message, options);
  }
}
