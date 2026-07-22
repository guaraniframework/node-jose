import type http from 'http';
import type https from 'https';

import { InvalidJsonWebKeyError } from '../errors/invalid-jsonwebkey.error';

/**
 * Fetches an X.509 PEM Certificate Chain from the provided URL.
 *
 * @param url X.509 PEM Certificate Chain URL.
 * @throws {InvalidJsonWebKeyError} Failed to parse the X.509 PEM Certificate Chain from the provided URL.
 * @returns X.509 PEM Certificate Chain.
 */
export async function getX509PemCertificateChainFromUrl(url: string): Promise<string[]> {
  const { get } = url.startsWith('https') ? (require('https') as typeof https) : (require('http') as typeof http);

  return new Promise((resolve, reject) => {
    get(url, (response) => {
      let data = '';

      response.on('data', (chunk: string) => (data += chunk));

      response.on('end', () => {
        const pemCertificates = data.match(
          /^-----BEGIN CERTIFICATE-----\r?\n((?:(?!-----).*\r?\n)*)-----END CERTIFICATE-----$/gm,
        );

        if (pemCertificates === null) {
          return reject(
            new InvalidJsonWebKeyError('Failed to parse the X.509 PEM Certificate Chain from the provided URL.'),
          );
        }

        return resolve(
          pemCertificates.map((pemCertificate) => {
            return pemCertificate.replace('-----BEGIN CERTIFICATE-----', '').replace('-----END CERTIFICATE-----', '');
          }),
        );
      });

      response.on('error', (error) => {
        return reject(
          new InvalidJsonWebKeyError('Failed to parse the X.509 PEM Certificate Chain from the provided URL.', {
            cause: error,
          }),
        );
      });
    });
  });
}
