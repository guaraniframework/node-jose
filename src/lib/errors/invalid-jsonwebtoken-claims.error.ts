import { JoseError } from './jose.error';

/**
 * Thrown when the provided JSON Web Token Claims is invalid.
 */
export class InvalidJsonWebTokenClaimsError extends JoseError {}
