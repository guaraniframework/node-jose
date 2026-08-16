import { Buffer } from 'buffer';

import { InvalidJsonWebTokenError } from '../../../errors/invalid-jsonwebtoken.error';
import { AESKWJsonWebEncryptionKeyManagementBackend } from '../../../jwa/jwe/alg/aeskw/aeskw-jsonwebencryption-key-management.backend';
import { AESCBCJsonWebEncryptionContentEncryptionBackend } from '../../../jwa/jwe/enc/aescbc/aescbc-jsonwebencryption-content-encryption.backend';
import { OctetSequenceJsonWebKey } from '../../../jwa/jwk/oct/octet-sequence.jsonwebkey';
import { JsonWebEncryptionHeaderParameters } from '../../../jwe/jsonwebencryption-header.parameters';
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

  const contentEncryptionKey = Buffer.from('BNMfxVSd_P4LZJ36P6pqzmt81C1vawnbyLEA8I-cLM8', 'base64url');
  const initializationVector = Buffer.from('AxY8DCtDaGlsbGljb3RoZQ', 'base64url');

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

    jest
      .spyOn(AESKWJsonWebEncryptionKeyManagementBackend.prototype, 'generateContentEncryptionKey')
      .mockResolvedValueOnce(contentEncryptionKey);

    jest
      .spyOn(AESCBCJsonWebEncryptionContentEncryptionBackend.prototype, 'generateInitializationVector')
      .mockResolvedValueOnce(initializationVector);
  });

  afterEach(() => {
    jest.useRealTimers();
    jest.restoreAllMocks();
  });

  it.each(invalidClaims)('should throw when the provided JSON Web Token Claims is invalid.', async (claims) => {
    await expect(serialize(claims, header)).rejects.toThrowWithMessage(
      TypeError,
      'The provided JSON Web Token Claims Parameters is invalid.',
    );
  });

  it.each(invalidProtectedHeaders)(
    'should throw when the provided JSON Web Encryption Protected Header is invalid.',
    async (protectedHeader) => {
      await expect(serialize(claims, protectedHeader)).rejects.toThrowWithMessage(
        InvalidJsonWebTokenError,
        'Failed to serialize the Encrypted JSON Web Token.',
      );
    },
  );

  it.each(invalidSerializeOptions)('should throw when the provided options is invalid.', async (options) => {
    await expect(serialize(claims, header, options)).rejects.toThrowWithMessage(
      InvalidJsonWebTokenError,
      'Failed to serialize the Encrypted JSON Web Token.',
    );
  });

  it.each(invalidJsonWebKeys)('should throw when the provided option "jsonWebKey" is invalid.', async (jsonWebKey) => {
    await expect(serialize(claims, header, { jsonWebKey })).rejects.toThrowWithMessage(
      InvalidJsonWebTokenError,
      'Failed to serialize the Encrypted JSON Web Token.',
    );
  });

  it('should throw when failing to serialize the Encrypted JSON Web Token.', async () => {
    await expect(serialize(claims, header)).rejects.toThrowWithMessage(
      InvalidJsonWebTokenError,
      'Failed to serialize the Encrypted JSON Web Token.',
    );
  });

  it('should serialize the Encrypted JSON Web Token.', async () => {
    await expect(serialize(claims, header, { jsonWebKey })).resolves.toStrictEqual(token);
  });
});
