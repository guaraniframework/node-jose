import http from 'http';
import https from 'https';
import { Stream } from 'stream';

import { jsonStringify } from '@guarani/primitives';

import { InvalidJsonWebKeySetError } from '../errors/invalid-jsonwebkeyset.error';
import { JsonWebKeySet } from '../jwks/jsonwebkeyset';
import { JsonWebKeySetParameters } from '../jwks/jsonwebkeyset.parameters';
import { getJsonWebKeySetFromUrl } from './get-jsonwebkeyset-from-url';

describe('getJsonWebKeySetFromUrl()', () => {
  const parameters: JsonWebKeySetParameters = {
    keys: [
      {
        kty: 'EC',
        crv: 'P-256',
        x: '4c_cS6IT6jaVQeobt_6BDCTmzBaBOTmmiSCpjd5a6Og',
        y: 'mnrPnCFTDkGdEwilabaqM7DzwlAFgetZTmP9ycHPxF8',
        kid: 'ec-kid',
      },
      {
        kty: 'RSA',
        n:
          'xjpFydzTbByzL5jhEa2yQO63dpS9d9SKaN107AR69skKiTR4uK1c4SzDt4YcurDB' +
          'yhgKNzeBo6Vq3IRrkrltp97LKWfeZdM-leGt8-UTZEWqrNf3UGOEj8kI6lbjiG-S' +
          'n_yNHcVA9qBV22norZkgXctHLeFbY6TmpD-I8_UiplZUHoc9KlYc7crCQRa-O7tK' +
          'FDULNTMjjifc0dmuYP7ZcYAZXmRmoOpQuDr8s7OZY7TAqN0btMfA7RpUCWLT6TMR' +
          'QPX8GcyTxfbkOrSTFueKMHVNdXDtl068XXJ9mkjORiEmwlzqSBoxdeLWcNf_u20S' +
          '5JG5iK0nsm1uZYu-02XN-w',
        e: 'AQAB',
        kid: 'rsa-kid',
      },
    ],
  };

  it('should throw when getting an error while calling the json web key set url.', async () => {
    https.get = jest.fn().mockImplementationOnce((_, callback) => {
      const stream = new Stream();
      callback(stream);
      stream.emit('data', 'aabbccddeeff');
      stream.emit('error', new Error('HTTP Error.'));
    });

    await expect(getJsonWebKeySetFromUrl('https://jwks-url.com')).rejects.toThrowWithMessage(
      InvalidJsonWebKeySetError,
      'Failed to parse a JSON Web Key Set from the provided URL.',
    );
  });

  it('should throw when the json web key set url returns an invalid json web key set.', async () => {
    http.get = jest.fn().mockImplementationOnce((_, callback) => {
      const stream = new Stream();
      callback(stream);
      stream.emit('data', 'aabbccddeeff');
      stream.emit('end');
    });

    await expect(getJsonWebKeySetFromUrl('http://jwks-url.com')).rejects.toThrowWithMessage(
      InvalidJsonWebKeySetError,
      'Failed to parse a JSON Web Key Set from the provided URL.',
    );
  });

  it('should return the json web key set.', async () => {
    let jsonWebKeySet!: JsonWebKeySet;

    http.get = jest.fn().mockImplementationOnce((_, callback) => {
      const stream = new Stream();
      callback(stream);
      stream.emit('data', jsonStringify(parameters));
      stream.emit('end');
    });

    await expect(async () => {
      jsonWebKeySet = await getJsonWebKeySetFromUrl('http://jwks-url.com');
    }).resolves.not.toThrow();

    expect(jsonWebKeySet).toBeInstanceOf(JsonWebKeySet);
    expect(jsonWebKeySet.keys.map((key) => key.parameters)).toStrictEqual(parameters.keys);
  });
});
