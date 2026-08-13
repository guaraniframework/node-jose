import { Buffer } from 'buffer';

import { InvalidJsonWebSignatureError } from '../../../errors/invalid-jsonwebsignature.error';
import { OctetSequenceJsonWebKey } from '../../../jwa/jwk/oct/octet-sequence.jsonwebkey';
import { JsonWebSignatureHeader } from '../../jsonwebsignature-header';
import { JsonWebSignatureHeaderParameters } from '../../jsonwebsignature-header.parameters';
import { CompactJsonWebSignature } from './compact-jsonwebsignature';
import { deserialize } from './deserialize';

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

const invalidDetachedPayloads: any[] = [
  undefined,
  null,
  true,
  1,
  1.2,
  1n,
  Symbol('a'),
  Buffer,
  () => 1,
  {},
  [],
  Buffer.alloc(0),
];

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

describe('deserialize()', () => {
  const wrongSignatureToken =
    'eyJhbGciOiJIUzI1NiJ9.' +
    'eyJpYXQiOiAxNzIzMDEwNDU1LCAic3ViIjogIjA3OEJXRERYYXNkY2c4In0.' +
    'oYyAwnx7D5WIo3L1WWx_zBSNX12nH8lwXQHgpPiApSk';

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

  const unencodedProtectedHeader: JsonWebSignatureHeaderParameters = { alg: 'HS256', b64: false, crit: ['b64'] };
  const encodedProtectedHeader: JsonWebSignatureHeaderParameters = { alg: 'HS256' };

  const payloadWithoutDot = Buffer.from('{"iat": 1723010455, "sub": "078BWDDXasdcg8"}', 'utf8');
  const payloadWithDot = Buffer.from('$.02', 'utf8');

  const jsonWebKey = new OctetSequenceJsonWebKey({ kty: 'oct', k: 'qDM80igvja4Tg_tNsEuWDhl2bMM6_NgJEldFhIEuwqQ' });

  it.each(invalidDeserializeOptions)('should throw when the provided options is invalid.', async (options) => {
    await expect(deserialize(encodedAttachedToken, options)).rejects.toThrowWithMessage(
      TypeError,
      'The provided options is invalid.',
    );
  });

  it.each(invalidJsonWebKeys)('should throw when the provided option "jsonWebKey" is invalid.', async (jsonWebKey) => {
    await expect(deserialize(encodedAttachedToken, { jsonWebKey })).rejects.toThrowWithMessage(
      TypeError,
      'The provided option "jsonWebKey" is invalid.',
    );
  });

  it.each(invalidExpectedAlgorithms)(
    'should throw when the provided option "expectedDigitalSignatureAlgorithms" is invalid.',
    async (expectedDigitalSignatureAlgorithms) => {
      await expect(
        deserialize(encodedAttachedToken, { expectedDigitalSignatureAlgorithms }),
      ).rejects.toThrowWithMessage(TypeError, 'The provided option "expectedDigitalSignatureAlgorithms" is invalid.');
    },
  );

  it.each(invalidDetachedPayloads)(
    'should throw when the provided option "detachedPayload" is invalid.',
    async (detachedPayload) => {
      await expect(deserialize(encodedDetachedToken, { detachedPayload })).rejects.toThrowWithMessage(
        TypeError,
        'The provided option "detachedPayload" is invalid.',
      );
    },
  );

  it.each(invalidTokens)(
    'should throw when the provided Compact JSON Web Signature Token is invalid.',
    async (token) => {
      await expect(deserialize(token)).rejects.toThrowWithMessage(
        TypeError,
        'The provided Compact JSON Web Signature Token is invalid.',
      );
    },
  );

  it('should throw when deserializing a Detached Compact JSON Web Signature Token and not providing a Detached Payload.', async () => {
    await expect(deserialize(encodedDetachedToken)).rejects.toThrowWithMessage(
      InvalidJsonWebSignatureError,
      'The JSON Web Signature requires a valid Payload.',
    );
  });

  it('should throw when providing a Detached Payload for a Compact JSON Web Signature Token that already has a Payload.', async () => {
    await expect(deserialize(encodedAttachedToken, { detachedPayload: payloadWithoutDot })).rejects.toThrowWithMessage(
      InvalidJsonWebSignatureError,
      'The provided JSON Web Signature already has a defined Payload.',
    );
  });

  it('should throw when the JSON Web Signature Digital Signature Algorithm of the Compact JSON Web Signature Token is unexpected.', async () => {
    await expect(
      deserialize(encodedAttachedToken, { expectedDigitalSignatureAlgorithms: ['HS512'] }),
    ).rejects.toThrowWithMessage(
      InvalidJsonWebSignatureError,
      'Unexpected JSON Web Signature Digital Signature Algorithm "HS256".',
    );
  });

  it('should throw when the provided Signature fails to deserialize the provided Compact JSON Web Signature Token.', async () => {
    await expect(deserialize(wrongSignatureToken, { jsonWebKey })).rejects.toThrow();
  });

  it('should return the deserialized Compact JSON Web Signature from an Attached Unencoded Compact JSON Web Signature Token without a dot.', async () => {
    let jsonWebSignature!: CompactJsonWebSignature;

    await expect(async () => {
      jsonWebSignature = await deserialize(unencodedAttachedTokenWithoutDot, { jsonWebKey });
    }).resolves.not.toThrow();

    expect(jsonWebSignature.protectedHeader).toBeInstanceOf(JsonWebSignatureHeader);
    expect(jsonWebSignature.protectedHeader.parameters).toStrictEqual(unencodedProtectedHeader);
    expect(jsonWebSignature.payload).toStrictEqual(payloadWithoutDot);
  });

  it('should return the deserialized Compact JSON Web Signature from a Detached Unencoded Compact JSON Web Signature Token without a dot.', async () => {
    let jsonWebSignature!: CompactJsonWebSignature;

    await expect(async () => {
      jsonWebSignature = await deserialize(unencodedDetachedTokenWithoutDot, {
        jsonWebKey,
        detachedPayload: payloadWithoutDot,
      });
    }).resolves.not.toThrow();

    expect(jsonWebSignature.protectedHeader).toBeInstanceOf(JsonWebSignatureHeader);
    expect(jsonWebSignature.protectedHeader.parameters).toStrictEqual(unencodedProtectedHeader);
    expect(jsonWebSignature.payload).toStrictEqual(payloadWithoutDot);
  });

  it('should return the deserialized Compact JSON Web Signature from a Detached Unencoded Compact JSON Web Signature Token with a dot.', async () => {
    let jsonWebSignature!: CompactJsonWebSignature;

    const jsonWebKey = new OctetSequenceJsonWebKey({
      kty: 'oct',
      k: 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow',
    });

    await expect(async () => {
      jsonWebSignature = await deserialize(unencodedDetachedTokenWithDot, {
        jsonWebKey,
        detachedPayload: payloadWithDot,
      });
    }).resolves.not.toThrow();

    expect(jsonWebSignature.protectedHeader).toBeInstanceOf(JsonWebSignatureHeader);
    expect(jsonWebSignature.protectedHeader.parameters).toStrictEqual(unencodedProtectedHeader);
    expect(jsonWebSignature.payload).toStrictEqual(payloadWithDot);
  });

  it('should return the deserialized Compact JSON Web Signature from an Attached Encoded Compact JSON Web Signature Token without a dot.', async () => {
    let jsonWebSignature!: CompactJsonWebSignature;

    await expect(async () => {
      jsonWebSignature = await deserialize(encodedAttachedToken, { jsonWebKey });
    }).resolves.not.toThrow();

    expect(jsonWebSignature.protectedHeader).toBeInstanceOf(JsonWebSignatureHeader);
    expect(jsonWebSignature.protectedHeader.parameters).toStrictEqual(encodedProtectedHeader);
    expect(jsonWebSignature.payload).toStrictEqual(payloadWithoutDot);
  });

  it('should return the deserialized Compact JSON Web Signature from a Detached Encoded Compact JSON Web Signature Token without a dot.', async () => {
    let jsonWebSignature!: CompactJsonWebSignature;

    await expect(async () => {
      jsonWebSignature = await deserialize(encodedDetachedToken, { jsonWebKey, detachedPayload: payloadWithoutDot });
    }).resolves.not.toThrow();

    expect(jsonWebSignature.protectedHeader).toBeInstanceOf(JsonWebSignatureHeader);
    expect(jsonWebSignature.protectedHeader.parameters).toStrictEqual(encodedProtectedHeader);
    expect(jsonWebSignature.payload).toStrictEqual(payloadWithoutDot);
  });
});
