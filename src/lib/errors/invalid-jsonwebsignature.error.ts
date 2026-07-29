import { JoseError } from './jose.error';

/**
 * Thrown when the provided JSON Web Signature is invalid.
 */
export class InvalidJsonWebSignatureError extends JoseError {}
