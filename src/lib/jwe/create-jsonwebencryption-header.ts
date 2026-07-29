import { isPlainObject } from '@guarani/primitives';

import { getJsonWebKeyFromJoseHeader } from '../utils/get-jsonwebkey-from-jose-header';
import { getX509CertificateChain } from '../utils/get-x509-certificate-chain';
import { validateJsonWebKeyAndX509CertificateChain } from '../utils/validate-jsonwebkey-and-x509-certificate-chain';
import { JsonWebEncryptionHeader } from './jsonwebencryption-header';
import { JsonWebEncryptionHeaderParameters } from './jsonwebencryption-header.parameters';

/**
 * Creates a JSON Web Encryption Header based on the provided JSON Web Encryption Header Parameters.
 *
 * @param parameters JSON Web Encryption Header Parameters.
 * @throws {TypeError} The provided JSON Web Encryption Header Parameters is invalid.
 * @throws {InvalidJoseHeaderError} The provided JSON Web Encryption Header Parameters are invalid.
 * @returns JSON Web Encryption Header.
 */
export async function createJsonWebEncryptionHeader(
  parameters: JsonWebEncryptionHeaderParameters,
): Promise<JsonWebEncryptionHeader> {
  if (!isPlainObject(parameters)) {
    throw new TypeError('The provided JSON Web Encryption Header Parameters is invalid.');
  }

  const header = new JsonWebEncryptionHeader(parameters);

  const jsonWebKey = await getJsonWebKeyFromJoseHeader(parameters);
  const certificateChain = await getX509CertificateChain(parameters);

  if (jsonWebKey !== null && certificateChain !== null) {
    validateJsonWebKeyAndX509CertificateChain(jsonWebKey.parameters, certificateChain);
  }

  header.jsonWebKey = jsonWebKey;
  header.certificateChain = certificateChain;

  return header;
}
