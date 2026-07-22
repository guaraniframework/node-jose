import { JoseError } from './jose.error';

/**
 * Thrown when the provided JSON Web Key is invalid.
 */
export class InvalidJsonWebKeyError extends JoseError {}
