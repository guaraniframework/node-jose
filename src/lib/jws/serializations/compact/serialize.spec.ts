import { Buffer } from 'buffer';

import { InvalidJsonWebSignatureError } from '../../../errors/invalid-jsonwebsignature.error';
import { OctetSequenceJsonWebKey } from '../../../jwa/jwk/oct/octet-sequence.jsonwebkey';
import { JsonWebSignatureHeaderParameters } from '../../jsonwebsignature-header.parameters';
import { serialize } from './serialize';

const invalidPayloads: any[] = [
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
  {},
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

const invalidDetacheds: any[] = [
  undefined,
  null,
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
  const unencodedAttachedTokenWithoutDot =
    'eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19.' +
    '{"iat": 1723010455, "sub": "078BWDDXasdcg8"}.' +
    'uXQJV7FqjHNukDJPwTa4wtywtIoQ9CiBf16ETgFeKjA';

  const unencodedDetachedTokenWithoutDot =
    'eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..uXQJV7FqjHNukDJPwTa4wtywtIoQ9CiBf16ETgFeKjA';

  const unencodedDetachedTokenWithDot =
    'eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..A5dxf2s96_n5FLueVuW1Z_vh161FwXZC4YLPff6dmDY';

  const encodedAttachedToken =
    'eyJhbGciOiJIUzI1NiJ9.' +
    'eyJpYXQiOiAxNzIzMDEwNDU1LCAic3ViIjogIjA3OEJXRERYYXNkY2c4In0.' +
    'hRqmKz7sKWQZyNM1Kw9AgqPNOedszPvEADYmNFo8foA';

  const encodedDetachedToken = 'eyJhbGciOiJIUzI1NiJ9..hRqmKz7sKWQZyNM1Kw9AgqPNOedszPvEADYmNFo8foA';

  const payloadWithoutDot = Buffer.from('{"iat": 1723010455, "sub": "078BWDDXasdcg8"}', 'utf8');
  const payloadWithDot = Buffer.from('$.02', 'utf8');

  const unencodedProtectedHeader: JsonWebSignatureHeaderParameters = { alg: 'HS256', b64: false, crit: ['b64'] };
  const encodedProtectedHeader: JsonWebSignatureHeaderParameters = { alg: 'HS256' };

  const jsonWebKey = new OctetSequenceJsonWebKey({ kty: 'oct', k: 'qDM80igvja4Tg_tNsEuWDhl2bMM6_NgJEldFhIEuwqQ' });

  it.each(invalidPayloads)('should throw when the provided Payload is invalid.', async (payload) => {
    await expect(serialize(payload, encodedProtectedHeader)).rejects.toThrowWithMessage(
      TypeError,
      'The provided Payload is invalid.',
    );
  });

  it.each(invalidProtectedHeaders)(
    'should throw when the provided JSON Web Signature Protected Header is invalid.',
    async (protectedHeader) => {
      await expect(serialize(payloadWithoutDot, protectedHeader)).rejects.toThrowWithMessage(
        TypeError,
        'The provided JSON Web Signature Protected Header is invalid.',
      );
    },
  );

  it.each(invalidSerializeOptions)('should throw when the provided options is invalid.', async (options) => {
    await expect(serialize(payloadWithoutDot, encodedProtectedHeader, options)).rejects.toThrowWithMessage(
      TypeError,
      'The provided options is invalid.',
    );
  });

  it.each(invalidJsonWebKeys)('should throw when the provided option "jsonWebKey" is invalid.', async (jsonWebKey) => {
    await expect(serialize(payloadWithoutDot, encodedProtectedHeader, { jsonWebKey })).rejects.toThrowWithMessage(
      TypeError,
      'The provided option "jsonWebKey" is invalid.',
    );
  });

  it.each(invalidDetacheds)('should throw when the provided option "detached" is invalid.', async (detached) => {
    await expect(serialize(payloadWithoutDot, encodedProtectedHeader, { detached })).rejects.toThrowWithMessage(
      TypeError,
      'The provided option "detached" is invalid.',
    );
  });

  it('should throw when serializing an Attached Unencoded Payload with a dot in its contents.', async () => {
    await expect(serialize(payloadWithDot, unencodedProtectedHeader)).rejects.toThrowWithMessage(
      InvalidJsonWebSignatureError,
      'The provided Unencoded Payload cannot be serialized.',
    );

    await expect(
      serialize(payloadWithDot, unencodedProtectedHeader, { jsonWebKey, detached: false }),
    ).rejects.toThrowWithMessage(InvalidJsonWebSignatureError, 'The provided Unencoded Payload cannot be serialized.');
  });

  it('should serialize a Compact JSON Web Signature Attached Unencoded Token without a dot.', async () => {
    await expect(serialize(payloadWithoutDot, unencodedProtectedHeader, { jsonWebKey })).resolves.toStrictEqual(
      unencodedAttachedTokenWithoutDot,
    );
  });

  it('should serialize a Compact JSON Web Signature Detached Unencoded Token without a dot.', async () => {
    await expect(
      serialize(payloadWithoutDot, unencodedProtectedHeader, { jsonWebKey, detached: true }),
    ).resolves.toStrictEqual(unencodedDetachedTokenWithoutDot);
  });

  it('should serialize a Compact JSON Web Signature Detached Unencoded Token with a dot.', async () => {
    const jsonWebKey = new OctetSequenceJsonWebKey({
      kty: 'oct',
      k: 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow',
    });

    await expect(
      serialize(payloadWithDot, unencodedProtectedHeader, { jsonWebKey, detached: true }),
    ).resolves.toStrictEqual(unencodedDetachedTokenWithDot);
  });

  it('should serialize a Compact JSON Web Signature Attached Encoded Token without a dot.', async () => {
    await expect(serialize(payloadWithoutDot, encodedProtectedHeader, { jsonWebKey })).resolves.toStrictEqual(
      encodedAttachedToken,
    );
  });

  it('should serialize a Compact JSON Web Signature Detached Encoded Token without a dot.', async () => {
    await expect(
      serialize(payloadWithoutDot, encodedProtectedHeader, { jsonWebKey, detached: true }),
    ).resolves.toStrictEqual(encodedDetachedToken);
  });
});
