import { JoseException } from './jose.exception';

/**
 * Raised when no JWK matches the criteria at the JWK Set.
 */
export class JwkNotFoundException extends JoseException {
  /**
   * Instantiates a new JWK Not Found Exception.
   *
   * @param message Error Message.
   */
  public constructor(message = 'No JWK matches the criteria at the JWK Set.', options?: ErrorOptions) {
    super(message, options);
  }
}
