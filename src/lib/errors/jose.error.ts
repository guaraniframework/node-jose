/**
 * Base JOSE Error class.
 */
export abstract class JoseError extends Error {
  /**
   * Instantiates a new JOSE Error.
   *
   * @param message Error message.
   */
  public constructor(message: string);

  /**
   * Instantiates a new JOSE Error.
   *
   * @param message Error message.
   * @param options Error options.
   */
  public constructor(message: string, options: ErrorOptions);

  /**
   * Instantiates a new JOSE Error.
   *
   * @param message Error message.
   * @param options Error options.
   */
  public constructor(message: string, options?: ErrorOptions) {
    super(message, options);
  }
}
