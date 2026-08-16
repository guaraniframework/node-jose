import { Buffer } from 'buffer';

import { InvalidJsonWebTokenError } from '../../../errors/invalid-jsonwebtoken.error';
import { JsonWebSignatureHeader } from '../../../jws/jsonwebsignature-header';
import { JsonWebSignatureHeaderParameters } from '../../../jws/jsonwebsignature-header.parameters';
import { JsonWebTokenClaims } from '../../jsonwebtoken-claims';
import { JsonWebTokenClaimsParameters } from '../../jsonwebtoken-claims.parameters';
import { decode } from './decode';
import { SignedJsonWebTokenParameters } from './signed-jsonwebtoken.parameters';

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

const invalidTokenFormats = ['a', '.a', 'a.b', 'a.b.c.d'];

describe('decode()', () => {
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
  const signature = Buffer.from('A8PXBUjCWevZJdOj2pixPGmve0vhm5lNjYsHiCFAL24', 'base64url');

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

  it.each(invalidTokens)('should throw when the provided Signed JSON Web Token is invalid.', async (token) => {
    await expect(decode(token)).rejects.toThrowWithMessage(TypeError, 'The provided Signed JSON Web Token is invalid.');
  });

  it.each(invalidTokenFormats)(
    'should throw when the provided Signed JSON Web Token has an invalid format.',
    async (token) => {
      await expect(decode(token)).rejects.toThrowWithMessage(
        InvalidJsonWebTokenError,
        'The provided JSON Web Token is invalid.',
      );
    },
  );

  it('should return the Signed JSON Web Token Parameters from the provided Signed JSON Web Token.', async () => {
    await expect(decode(token)).resolves.toStrictEqual<SignedJsonWebTokenParameters>({
      header: new JsonWebSignatureHeader(header),
      claims: new JsonWebTokenClaims(claims),
      signature,
    });
  });
});
