import { JoseError } from './jose.error';

/**
 * Thrown when the provided JSON Web Token is invalid.
 */
export class InvalidJsonWebTokenError extends JoseError {}
