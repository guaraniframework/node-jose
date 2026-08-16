import { Buffer } from 'buffer';

import { InvalidJsonWebTokenError } from '../../../errors/invalid-jsonwebtoken.error';
import { OctetSequenceJsonWebKey } from '../../../jwa/jwk/oct/octet-sequence.jsonwebkey';
import { JsonWebSignatureHeaderParameters } from '../../../jws/jsonwebsignature-header.parameters';
import { JsonWebTokenClaimsParameters } from '../../jsonwebtoken-claims.parameters';
import { serialize } from './serialize';

const invalidClaims: any[] = [
  undefined,
  null,
  true,
  1,
  1.2,
  1n,
  'a',
  Symbol('a'),
  Buffer,
  () => 1,
  [],
  Buffer.alloc(0),
];

const invalidProtectedHeaders: any[] = [
  undefined,
  null,
  true,
  1,
  1.2,
  1n,
  'a',
  Symbol('a'),
  Buffer,
  Buffer.alloc(1),
  () => 1,
  [],
];

const invalidSerializeOptions: any[] = [null, true, 1, 1.2, 1n, 'a', Symbol('a'), Buffer, Buffer.alloc(1), () => 1, []];

const invalidJsonWebKeys: any[] = [
  undefined,
  null,
  true,
  1,
  1.2,
  1n,
  'a',
  Symbol('a'),
  Buffer,
  Buffer.alloc(1),
  () => 1,
  {},
  [],
];

describe('serialize()', () => {
  let now!: number;
  let claims!: JsonWebTokenClaimsParameters;

  const token =
    'eyJhbGciOiJIUzI1NiJ9.' +
    'eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlLmNvbSIsInN1YiI6Imh0dHBz' +
    'Oi8vc3ViamVjdC5leGFtcGxlLmNvbSIsImF1ZCI6Imh0dHBzOi8vYXVkaWVuY2Uu' +
    'ZXhhbXBsZS5jb20iLCJleHAiOjE3ODY1MDcyMDAsIm5iZiI6MTc4NjUwMzYwMCwi' +
    'aWF0IjoxNzg2NTAzNjAwLCJqdGkiOiI3NTgxMDFhYy1jZTgyLTQ5ZTQtOWQ0My0x' +
    'ZTViZmM2MjI1OTMifQ.' +
    'A8PXBUjCWevZJdOj2pixPGmve0vhm5lNjYsHiCFAL24';

  const header: JsonWebSignatureHeaderParameters = { alg: 'HS256' };

  const jsonWebKey = new OctetSequenceJsonWebKey({ kty: 'oct', k: 'qDM80igvja4Tg_tNsEuWDhl2bMM6_NgJEldFhIEuwqQ' });

  beforeEach(() => {
    jest.useFakeTimers({ now: new Date(2026, 7, 12, 0, 0, 0, 0) });

    now = Math.floor(Date.now() / 1000);

    claims = {
      iss: 'https://issuer.example.com',
      sub: 'https://subject.example.com',
      aud: 'https://audience.example.com',
      exp: now + 3600,
      nbf: now,
      iat: now,
      jti: '758101ac-ce82-49e4-9d43-1e5bfc622593',
    };
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  it.each(invalidClaims)('should throw when the provided JSON Web Token Claims is invalid.', async (claims) => {
    await expect(serialize(claims, header)).rejects.toThrowWithMessage(
      TypeError,
      'The provided JSON Web Token Claims Parameters is invalid.',
    );
  });

  it.each(invalidProtectedHeaders)(
    'should throw when the provided JSON Web Signature Protected Header is invalid.',
    async (protectedHeader) => {
      await expect(serialize(claims, protectedHeader)).rejects.toThrowWithMessage(
        InvalidJsonWebTokenError,
        'Failed to serialize the Signed JSON Web Token.',
      );
    },
  );

  it.each(invalidSerializeOptions)('should throw when the provided options is invalid.', async (options) => {
    await expect(serialize(claims, header, options)).rejects.toThrowWithMessage(
      InvalidJsonWebTokenError,
      'Failed to serialize the Signed JSON Web Token.',
    );
  });

  it.each(invalidJsonWebKeys)('should throw when the provided option "jsonWebKey" is invalid.', async (jsonWebKey) => {
    await expect(serialize(claims, header, { jsonWebKey })).rejects.toThrowWithMessage(
      InvalidJsonWebTokenError,
      'Failed to serialize the Signed JSON Web Token.',
    );
  });

  it('should throw when failing to serialize the Signed JSON Web Token.', async () => {
    await expect(serialize(claims, header)).rejects.toThrowWithMessage(
      InvalidJsonWebTokenError,
      'Failed to serialize the Signed JSON Web Token.',
    );
  });

  it('should serialize the Signed JSON Web Token.', async () => {
    await expect(serialize(claims, header, { jsonWebKey })).resolves.toStrictEqual(token);
  });
});
