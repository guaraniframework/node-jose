import { JoseError } from './jose.error';

/**
 * Thrown when the provided JOSE Header is invalid.
 */
export class InvalidJoseHeaderError extends JoseError {}
