import { Buffer } from 'buffer';

import { InvalidJsonWebTokenError } from '../../../errors/invalid-jsonwebtoken.error';
import { OctetSequenceJsonWebKey } from '../../../jwa/jwk/oct/octet-sequence.jsonwebkey';
import { JsonWebSignatureHeader } from '../../../jws/jsonwebsignature-header';
import { JsonWebSignatureHeaderParameters } from '../../../jws/jsonwebsignature-header.parameters';
import { JsonWebTokenClaims } from '../../jsonwebtoken-claims';
import { JsonWebTokenClaimsParameters } from '../../jsonwebtoken-claims.parameters';
import { deserialize } from './deserialize';
import { SignedJsonWebToken } from './signed-jsonwebtoken';

const invalidTokens: any[] = [
  undefined,
  null,
  true,
  1,
  1.2,
  1n,
  Symbol('a'),
  Buffer,
  Buffer.alloc(1),
  () => 1,
  {},
  [],
  '',
];

const invalidDeserializeOptions: any[] = [
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

const invalidJsonWebKeys: any[] = [
  undefined,
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

const invalidExpectedAlgorithms: any[] = [
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
  ['a'],
];

describe('deserialize()', () => {
  let now!: number;
  let claims!: JsonWebTokenClaimsParameters;

  const wrongPayloadToken = 'eyJhbGciOiJIUzI1NiJ9.e30.A8PXBUjCWevZJdOj2pixPGmve0vhm5lNjYsHiCFAL24';

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

  it.each(invalidTokens)('should throw when the provided JSON Web Token is invalid.', async (token) => {
    await expect(deserialize(token)).rejects.toThrowWithMessage(
      InvalidJsonWebTokenError,
      'The provided JSON Web Token is invalid.',
    );
  });

  it.each(invalidDeserializeOptions)('should throw when the provided options is invalid.', async (options) => {
    await expect(deserialize(token, options)).rejects.toThrowWithMessage(
      InvalidJsonWebTokenError,
      'The provided JSON Web Token is invalid.',
    );
  });

  it.each(invalidJsonWebKeys)('should throw when the provided option "jsonWebKey" is invalid.', async (jsonWebKey) => {
    await expect(deserialize(token, { jsonWebKey })).rejects.toThrowWithMessage(
      InvalidJsonWebTokenError,
      'The provided JSON Web Token is invalid.',
    );
  });

  it.each(invalidExpectedAlgorithms)(
    'should throw when the provided option "expectedDigitalSignatureAlgorithms" is invalid.',
    async (expectedDigitalSignatureAlgorithms) => {
      await expect(deserialize(token, { expectedDigitalSignatureAlgorithms })).rejects.toThrowWithMessage(
        InvalidJsonWebTokenError,
        'The provided JSON Web Token is invalid.',
      );
    },
  );

  it('should throw when the payload of the provided Signed JSON Web Token is invalid.', async () => {
    await expect(deserialize(wrongPayloadToken, { jsonWebKey })).rejects.toThrowWithMessage(
      InvalidJsonWebTokenError,
      'The provided JSON Web Token is invalid.',
    );
  });

  it('should return the deserialized Signed JSON Web Token.', async () => {
    let jsonWebToken!: SignedJsonWebToken;

    await expect(async () => (jsonWebToken = await deserialize(token, { jsonWebKey }))).resolves.not.toThrow();

    expect(jsonWebToken.claims).toBeInstanceOf(JsonWebTokenClaims);
    expect(jsonWebToken.claims.parameters).toStrictEqual(claims);

    expect(jsonWebToken.header).toBeInstanceOf(JsonWebSignatureHeader);
    expect(jsonWebToken.header.parameters).toStrictEqual(header);
  });
});
