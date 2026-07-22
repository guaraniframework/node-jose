import { Buffer } from 'buffer';
import { X509Certificate } from 'crypto';

import { InvalidJsonWebKeyError } from '../errors/invalid-jsonwebkey.error';
import { getX509PemCertificateChainFromUrl } from './get-x509-pem-certificate-chain-from-url';

interface X509CertificateChainParameters {
  readonly x5u?: string;
  readonly x5c?: string[];
  readonly x5t?: string;
  readonly 'x5t#S256'?: string;
}

/**
 * Parses and validates an X.509 Certificate Chain from the provided parameters.
 *
 * @param parameters Parameters containing the X.509 Certificate Chain or its URL.
 * @throws {InvalidJsonWebKeyError} Failed to parse the X.509 Certificate Chain from the provided Parameters.
 * @returns X.509 Certificate Chain.
 */
export async function getX509CertificateChain(
  parameters: X509CertificateChainParameters,
): Promise<X509Certificate[] | null> {
  if (!('x5u' in parameters) && !('x5c' in parameters)) {
    return null;
  }

  const pemCertificateChain: string[] =
    'x5u' in parameters ? await getX509PemCertificateChainFromUrl(parameters.x5u) : parameters.x5c!;

  let certificateChain!: X509Certificate[];

  try {
    certificateChain = pemCertificateChain.map((pemCertificate) => {
      return new X509Certificate(Buffer.from(pemCertificate, 'base64'));
    });
  } catch (error: unknown) {
    throw new InvalidJsonWebKeyError('One or more X.509 Certificates are invalid.', { cause: error });
  }

  // TODO: Check keyUsage and signatureAlgorithm
  const now = new Date();

  if (certificateChain.some((certificate) => now < certificate.validFromDate)) {
    throw new InvalidJsonWebKeyError('One or more X.509 Certificates are not yet valid.');
  }

  if (certificateChain.some((certificate) => now >= certificate.validToDate)) {
    throw new InvalidJsonWebKeyError('One or more X.509 Certificates are expired.');
  }

  for (let i = 0; i < certificateChain.length - 1; i++) {
    const currentCertificate = certificateChain[i]!;
    const nextCertificate = certificateChain[i + 1]!;

    if (!currentCertificate.verify(nextCertificate.publicKey)) {
      throw new InvalidJsonWebKeyError('Invalid X.509 Certificate Chain.');
    }
  }

  if (typeof parameters.x5t !== 'undefined') {
    const fingerprint = Buffer.from(certificateChain[0]!.fingerprint.replaceAll(':', ''), 'hex');
    const thumbprint = Buffer.from(parameters.x5t, 'base64url');

    if (!fingerprint.equals(thumbprint)) {
      throw new InvalidJsonWebKeyError('Mismatching X.509 Certificate SHA-1 Thumbprint.');
    }
  }

  if (typeof parameters['x5t#S256'] !== 'undefined') {
    const fingerprint = Buffer.from(certificateChain[0]!.fingerprint256.replaceAll(':', ''), 'hex');
    const thumbprint = Buffer.from(parameters['x5t#S256'], 'base64url');

    if (!fingerprint.equals(thumbprint)) {
      throw new InvalidJsonWebKeyError('Mismatching X.509 Certificate SHA-256 Thumbprint.');
    }
  }

  return certificateChain;
}
