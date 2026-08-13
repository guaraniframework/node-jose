import { InvalidJoseHeaderError } from '../errors/invalid-jose-header.error';
import { JoseHeaderParameters } from '../jose/jose-header.parameters';
import { create } from '../jwk/create';
import { JsonWebKey } from '../jwk/jsonwebkey';
import { getJsonWebKeySetFromUrl } from './get-jsonwebkeyset-from-url';

/**
 * Gets a JSON Web Key from the provided JOSE Header Parameters.
 *
 * @param parameters JOSE Header Parameters.
 * @throws {InvalidJoseHeaderError} The provided JOSE Header Parameters are invalid.
 * @returns JSON Web Key from the provided JOSE Header Parameters.
 */
export async function getJsonWebKeyFromJoseHeader(parameters: JoseHeaderParameters): Promise<JsonWebKey | null> {
  if (!('jku' in parameters) && !('jwk' in parameters)) {
    return null;
  }

  let jsonWebKey!: JsonWebKey;

  if ('jku' in parameters) {
    try {
      jsonWebKey = (await getJsonWebKeySetFromUrl(parameters.jku)).get((jwk) => jwk.kid === parameters.kid);
    } catch (error: unknown) {
      throw new InvalidJoseHeaderError('Invalid JOSE Header Parameter "jku".', { cause: error });
    }
  }

  if ('jwk' in parameters) {
    if ('kid' in parameters && parameters.kid !== parameters.jwk.kid) {
      throw new InvalidJoseHeaderError('Mismatching JOSE Header and JSON Web Key Parameters "kid".');
    }

    try {
      jsonWebKey = await create(parameters.jwk);
    } catch (error: unknown) {
      throw new InvalidJoseHeaderError('Invalid JOSE Header Parameter "jwk".', { cause: error });
    }
  }

  if ('alg' in jsonWebKey.parameters && jsonWebKey.parameters.alg !== parameters.alg) {
    throw new InvalidJoseHeaderError('Mismatching JOSE Header and JSON Web Key Parameters "alg".');
  }

  return jsonWebKey;
}
