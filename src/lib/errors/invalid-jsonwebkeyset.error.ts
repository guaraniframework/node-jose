import { JoseError } from './jose.error';

/**
 * Thrown when the provided JSON Web Key Set is invalid.
 */
export class InvalidJsonWebKeySetError extends JoseError {}
