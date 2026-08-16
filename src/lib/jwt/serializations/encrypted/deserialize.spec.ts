import { Buffer } from 'buffer';

import { InvalidJsonWebTokenError } from '../../../errors/invalid-jsonwebtoken.error';
import { OctetSequenceJsonWebKey } from '../../../jwa/jwk/oct/octet-sequence.jsonwebkey';
import { JsonWebEncryptionHeader } from '../../../jwe/jsonwebencryption-header';
import { JsonWebEncryptionHeaderParameters } from '../../../jwe/jsonwebencryption-header.parameters';
import { JsonWebTokenClaims } from '../../jsonwebtoken-claims';
import { JsonWebTokenClaimsParameters } from '../../jsonwebtoken-claims.parameters';
import { deserialize } from './deserialize';
import { EncryptedJsonWebToken } from './encrypted-jsonwebtoken';

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

  const missingCiphertextToken =
    'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.' +
    '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ.' +
    'AxY8DCtDaGlsbGljb3RoZQ.' +
    '.' +
    'FYJuxuNgWc45ek7eLeNJNQ';

  const token =
    'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.' +
    '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ.' +
    'AxY8DCtDaGlsbGljb3RoZQ.' +
    'FgA-dGeGpV_KbHo21rm9iyadtKRGK3ltsG-qzALFjmqapZ9g0pcLo3VGGoGr6SM1' +
    'lRkKHp9aSLswiWYjSsSYV8OETrMDyw3zDZTQuGvSQzTfmqeEymto5Np5H8tAEOfX' +
    'CnMddBwg0QEWpMu9s6FcNy_rsTuJDbce1J2FpaIDRADHEui7rIrISlLDIu0tAOOF' +
    'wJtztt00tEyhjce9QE9qMn0pSI8_4z8CbXFVM1rJih4WuNso3qlmlsQLg_So3icA' +
    '6QpxXJ0pJhjEkS6pJhRRJw.' +
    'FYJuxuNgWc45ek7eLeNJNQ';

  const header: JsonWebEncryptionHeaderParameters = { alg: 'A128KW', enc: 'A128CBC-HS256' };

  const jsonWebKey = new OctetSequenceJsonWebKey({ kty: 'oct', k: 'GawgguFyGrWKav7AX4VKUg' });

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
    'should throw when the provided option "expectedKeyManagementAlgorithms" is invalid.',
    async (expectedKeyManagementAlgorithms) => {
      await expect(deserialize(token, { expectedKeyManagementAlgorithms })).rejects.toThrowWithMessage(
        InvalidJsonWebTokenError,
        'The provided JSON Web Token is invalid.',
      );
    },
  );

  it.each(invalidExpectedAlgorithms)(
    'should throw when the provided option "expectedContentEncryptionAlgorithms" is invalid.',
    async (expectedContentEncryptionAlgorithms) => {
      await expect(deserialize(token, { expectedContentEncryptionAlgorithms })).rejects.toThrowWithMessage(
        InvalidJsonWebTokenError,
        'The provided JSON Web Token is invalid.',
      );
    },
  );

  it.each(invalidExpectedAlgorithms)(
    'should throw when the provided option "expectedCompressionAlgorithms" is invalid.',
    async (expectedCompressionAlgorithms) => {
      await expect(deserialize(token, { expectedCompressionAlgorithms })).rejects.toThrowWithMessage(
        InvalidJsonWebTokenError,
        'The provided JSON Web Token is invalid.',
      );
    },
  );

  it.each(invalidTokens)('should throw when the provided JSON Web Token is invalid.', async (token) => {
    await expect(deserialize(token)).rejects.toThrowWithMessage(
      InvalidJsonWebTokenError,
      'The provided JSON Web Token is invalid.',
    );
  });

  it('should throw when the provided Encrypted JSON Web Token is missing a Ciphertext.', async () => {
    await expect(deserialize(missingCiphertextToken)).rejects.toThrowWithMessage(
      InvalidJsonWebTokenError,
      'The provided JSON Web Token is invalid.',
    );
  });

  it('should return the deserialized Encrypted JSON Web Token.', async () => {
    let jsonWebToken!: EncryptedJsonWebToken;

    await expect(async () => (jsonWebToken = await deserialize(token, { jsonWebKey }))).resolves.not.toThrow();

    expect(jsonWebToken.claims).toBeInstanceOf(JsonWebTokenClaims);
    expect(jsonWebToken.claims.parameters).toStrictEqual(claims);

    expect(jsonWebToken.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jsonWebToken.header.parameters).toStrictEqual(header);
  });
});
