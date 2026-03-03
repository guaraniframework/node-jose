import { JoseException } from './jose.exception';

/**
 * Raised when the provided Jose Header is invalid.
 */
export class InvalidJoseHeaderException extends JoseException {
  /**
   * Instantiates a new Invalid Jose Header Exception.
   *
   * @param message Error Message.
   */
  public constructor(message = 'The provided Jose Header is invalid.', options?: ErrorOptions) {
    super(message, options);
  }
}
