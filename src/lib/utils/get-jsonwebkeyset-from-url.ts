import type http from 'http';
import type https from 'https';

import { jsonParse } from '@guarani/primitives';

import { InvalidJsonWebKeySetError } from '../errors/invalid-jsonwebkeyset.error';
import { create } from '../jwks/create';
import { JsonWebKeySet } from '../jwks/jsonwebkeyset';

/**
 * Fetches a JSON Web Key Set from the provided URL.
 *
 * @param url JSON Web Key Set URL.
 * @throws {InvalidJsonWebKeySetError} Failed to parse a JSON Web Key Set from the provided URL.
 * @returns JSON Web Key Set.
 */
export async function getJsonWebKeySetFromUrl(url: string): Promise<JsonWebKeySet> {
  const { get } = url.startsWith('https') ? (require('https') as typeof https) : (require('http') as typeof http);

  return new Promise((resolve, reject) => {
    get(url, (response) => {
      let data = '';

      response.on('data', (chunk: string) => (data += chunk));

      response.on('end', async () => {
        try {
          return resolve(await create(jsonParse(data)));
        } catch (error: unknown) {
          return reject(
            new InvalidJsonWebKeySetError('Failed to parse a JSON Web Key Set from the provided URL.', {
              cause: error,
            }),
          );
        }
      });

      response.on('error', (error) => {
        return reject(
          new InvalidJsonWebKeySetError('Failed to parse a JSON Web Key Set from the provided URL.', { cause: error }),
        );
      });
    });
  });
}
