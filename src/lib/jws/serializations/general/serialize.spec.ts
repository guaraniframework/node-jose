import { Buffer } from 'buffer';

import { InvalidJoseHeaderError } from '../../../errors/invalid-jose-header.error';
import { InvalidJsonWebSignatureError } from '../../../errors/invalid-jsonwebsignature.error';
import { OctetSequenceJsonWebKey } from '../../../jwa/jwk/oct/octet-sequence.jsonwebkey';
import { JsonWebSignatureHeaderParameters } from '../../jsonwebsignature-header.parameters';
import { GeneralJsonWebSignatureToken } from './general-jsonwebsignature.token';
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

const invalidHeaders: any[] = [
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
  {},
  [],
  [undefined],
  [null],
  [true],
  [1],
  [1.2],
  [1n],
  ['a'],
  [Symbol('a')],
  [Buffer],
  [Buffer.alloc(1)],
  [[]],
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

const invalidUnprotectedHeaders: any[] = [
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
  [undefined],
  [true],
  [1],
  [1.2],
  [1n],
  ['a'],
  [Symbol('a')],
  [Buffer],
  [Buffer.alloc(1)],
  [() => 1],
  [{}],
  [[]],
  [
    new OctetSequenceJsonWebKey({ kty: 'oct', k: '0123456789abcdef' }),
    new OctetSequenceJsonWebKey({ kty: 'oct', k: '0123456789abcdef' }),
  ],
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
  // #region Unencoded Attached Token Without Dot
  const unencodedProtectedAttachedTokenWithoutDot: GeneralJsonWebSignatureToken = {
    payload: '{"iat": 1723010455, "sub": "078BWDDXasdcg8"}',
    signatures: [
      {
        protected: 'eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19',
        signature: 'uXQJV7FqjHNukDJPwTa4wtywtIoQ9CiBf16ETgFeKjA',
      },
    ],
  };

  const unencodedFullAttachedTokenWithoutDot: GeneralJsonWebSignatureToken = {
    payload: '{"iat": 1723010455, "sub": "078BWDDXasdcg8"}',
    signatures: [
      {
        protected: 'eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19',
        header: { kid: 'e9bc097a-ce51-4036-9562-d2ade882db0d' },
        signature: 'uXQJV7FqjHNukDJPwTa4wtywtIoQ9CiBf16ETgFeKjA',
      },
    ],
  };
  // #endregion
  // #region Unencoded Detached Token Without Dot
  const unencodedProtectedDetachedTokenWithoutDot: GeneralJsonWebSignatureToken = {
    signatures: [
      {
        protected: 'eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19',
        signature: 'uXQJV7FqjHNukDJPwTa4wtywtIoQ9CiBf16ETgFeKjA',
      },
    ],
  };

  const unencodedFullDetachedTokenWithoutDot: GeneralJsonWebSignatureToken = {
    signatures: [
      {
        protected: 'eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19',
        header: { kid: 'e9bc097a-ce51-4036-9562-d2ade882db0d' },
        signature: 'uXQJV7FqjHNukDJPwTa4wtywtIoQ9CiBf16ETgFeKjA',
      },
    ],
  };
  // #endregion
  // #region Unencoded Detached Token With Dot
  const unencodedProtectedDetachedTokenWithDot: GeneralJsonWebSignatureToken = {
    signatures: [
      {
        protected: 'eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19',
        signature: 'Tb6KReuvHIM29TcHMTRZwMJAAs5zuCSX4gTMSplXjEs',
      },
    ],
  };

  const unencodedFullDetachedTokenWithDot: GeneralJsonWebSignatureToken = {
    signatures: [
      {
        protected: 'eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19',
        header: { kid: 'e9bc097a-ce51-4036-9562-d2ade882db0d' },
        signature: 'Tb6KReuvHIM29TcHMTRZwMJAAs5zuCSX4gTMSplXjEs',
      },
    ],
  };
  // #endregion
  // #region Encoded Attached Token
  const encodedProtectedAttachedToken: GeneralJsonWebSignatureToken = {
    payload: 'eyJpYXQiOiAxNzIzMDEwNDU1LCAic3ViIjogIjA3OEJXRERYYXNkY2c4In0',
    signatures: [{ protected: 'eyJhbGciOiJIUzI1NiJ9', signature: 'hRqmKz7sKWQZyNM1Kw9AgqPNOedszPvEADYmNFo8foA' }],
  };

  const encodedUnprotectedAttachedToken: GeneralJsonWebSignatureToken = {
    payload: 'eyJpYXQiOiAxNzIzMDEwNDU1LCAic3ViIjogIjA3OEJXRERYYXNkY2c4In0',
    signatures: [
      {
        header: { alg: 'HS256', kid: 'e9bc097a-ce51-4036-9562-d2ade882db0d' },
        signature: 'iRxcRLDYSMrd3ZlYZ_tUXP8pRAShmoErGTo4sEsew3U',
      },
    ],
  };

  const encodedFullAttachedToken: GeneralJsonWebSignatureToken = {
    payload: 'eyJpYXQiOiAxNzIzMDEwNDU1LCAic3ViIjogIjA3OEJXRERYYXNkY2c4In0',
    signatures: [
      {
        protected: 'eyJhbGciOiJIUzI1NiJ9',
        header: { kid: 'e9bc097a-ce51-4036-9562-d2ade882db0d' },
        signature: 'hRqmKz7sKWQZyNM1Kw9AgqPNOedszPvEADYmNFo8foA',
      },
    ],
  };
  // #endregion
  // #region Encoded Detached Token
  const encodedProtectedDetachedToken: GeneralJsonWebSignatureToken = {
    signatures: [{ protected: 'eyJhbGciOiJIUzI1NiJ9', signature: 'hRqmKz7sKWQZyNM1Kw9AgqPNOedszPvEADYmNFo8foA' }],
  };

  const encodedUnprotectedDetachedToken: GeneralJsonWebSignatureToken = {
    signatures: [
      {
        header: { alg: 'HS256', kid: 'e9bc097a-ce51-4036-9562-d2ade882db0d' },
        signature: 'iRxcRLDYSMrd3ZlYZ_tUXP8pRAShmoErGTo4sEsew3U',
      },
    ],
  };

  const encodedFullDetachedToken: GeneralJsonWebSignatureToken = {
    signatures: [
      {
        protected: 'eyJhbGciOiJIUzI1NiJ9',
        header: { kid: 'e9bc097a-ce51-4036-9562-d2ade882db0d' },
        signature: 'hRqmKz7sKWQZyNM1Kw9AgqPNOedszPvEADYmNFo8foA',
      },
    ],
  };
  // #endregion

  const unencodedProtectedHeader: Partial<JsonWebSignatureHeaderParameters> = {
    alg: 'HS256',
    b64: false,
    crit: ['b64'],
  };
  const encodedProtectedHeader: Partial<JsonWebSignatureHeaderParameters> = { alg: 'HS256' };
  const unprotectedHeader: Partial<JsonWebSignatureHeaderParameters> = { kid: 'e9bc097a-ce51-4036-9562-d2ade882db0d' };

  const payloadWithoutDot = Buffer.from('{"iat": 1723010455, "sub": "078BWDDXasdcg8"}', 'utf8');
  const payloadWithDot = Buffer.from('$.02', 'utf8');

  const jsonWebKey = new OctetSequenceJsonWebKey({ kty: 'oct', k: 'qDM80igvja4Tg_tNsEuWDhl2bMM6_NgJEldFhIEuwqQ' });

  it.each(invalidPayloads)('should throw when the provided Payload is invalid.', async (payload) => {
    await expect(
      serialize(payload, [{ protectedHeader: encodedProtectedHeader, unprotectedHeader }]),
    ).rejects.toThrowWithMessage(TypeError, 'The provided Payload is invalid.');
  });

  it.each(invalidHeaders)('should throw when the provided JSON Web Signature Headers is invalid.', async (headers) => {
    await expect(serialize(payloadWithoutDot, headers)).rejects.toThrowWithMessage(
      TypeError,
      'The provided JSON Web Signature Headers is invalid.',
    );
  });

  it.each(invalidProtectedHeaders)(
    'should throw when the provided JSON Web Signature Protected Header is invalid.',
    async (protectedHeader) => {
      await expect(serialize(payloadWithoutDot, [{ protectedHeader, unprotectedHeader }])).rejects.toThrowWithMessage(
        TypeError,
        'The provided JSON Web Signature Protected Header is invalid.',
      );
    },
  );

  it.each(invalidUnprotectedHeaders)(
    'should throw when the provided JSON Web Signature Unprotected Header is invalid.',
    async (unprotectedHeader) => {
      await expect(
        serialize(payloadWithoutDot, [{ protectedHeader: encodedProtectedHeader, unprotectedHeader }]),
      ).rejects.toThrowWithMessage(TypeError, 'The provided JSON Web Signature Unprotected Header is invalid.');
    },
  );

  it('should throw when no JSON Web Signature Header is provided.', async () => {
    await expect(serialize(payloadWithoutDot, [{}])).rejects.toThrowWithMessage(
      InvalidJoseHeaderError,
      'Missing at least one required JSON Web Signature Header.',
    );
  });

  it('should throw when there are repeated JSON Web Signature Header Parameters.', async () => {
    await expect(
      serialize(payloadWithoutDot, [
        { protectedHeader: encodedProtectedHeader, unprotectedHeader: encodedProtectedHeader },
      ]),
    ).rejects.toThrowWithMessage(InvalidJoseHeaderError, 'Cannot have repeated JSON Web Signature Header Parameters.');
  });

  it('should throw if the JOSE Header Parameter "crit" is present in the Unprotected Header.', async () => {
    await expect(
      serialize(payloadWithoutDot, [
        { protectedHeader: encodedProtectedHeader, unprotectedHeader: { crit: ['foo'], foo: 'foo' } },
      ]),
    ).rejects.toThrowWithMessage(InvalidJoseHeaderError, 'Invalid Unprotected JOSE Header Parameter "crit".');
  });

  it('should throw if the JOSE Header Parameter "b64" is present in the Unprotected Header.', async () => {
    await expect(
      serialize(payloadWithoutDot, [{ protectedHeader: encodedProtectedHeader, unprotectedHeader: { b64: false } }]),
    ).rejects.toThrowWithMessage(InvalidJoseHeaderError, 'Invalid Unprotected JOSE Header Parameter "b64".');
  });

  it('should throw when the JSON Web Signature Headers Parameter "b64" mismatch.', async () => {
    await expect(
      serialize(payloadWithoutDot, [
        { protectedHeader: encodedProtectedHeader },
        { protectedHeader: unencodedProtectedHeader },
      ]),
    ).rejects.toThrowWithMessage(InvalidJoseHeaderError, 'Mismatching JSON Web Signature Headers Parameter "b64".');
  });

  it.each(invalidSerializeOptions)('should throw when the provided options is invalid.', async (options) => {
    await expect(
      serialize(payloadWithoutDot, [{ protectedHeader: encodedProtectedHeader, unprotectedHeader }], options),
    ).rejects.toThrowWithMessage(TypeError, 'The provided options is invalid.');
  });

  it.each(invalidJsonWebKeys)(
    'should throw when the provided option "jsonWebKeys" is invalid.',
    async (jsonWebKeys) => {
      await expect(
        serialize(payloadWithoutDot, [{ protectedHeader: encodedProtectedHeader, unprotectedHeader }], { jsonWebKeys }),
      ).rejects.toThrowWithMessage(TypeError, 'The provided option "jsonWebKeys" is invalid.');
    },
  );

  it.each(invalidDetacheds)('should throw when the provided option "detached" is invalid.', async (detached) => {
    await expect(
      serialize(payloadWithoutDot, [{ protectedHeader: encodedProtectedHeader, unprotectedHeader }], { detached }),
    ).rejects.toThrowWithMessage(TypeError, 'The provided option "detached" is invalid.');
  });

  it('should throw when serializing an Attached Unencoded Payload with a dot in its contents.', async () => {
    await expect(serialize(payloadWithDot, [{ protectedHeader: unencodedProtectedHeader }])).rejects.toThrowWithMessage(
      InvalidJsonWebSignatureError,
      'The provided Unencoded Payload cannot be serialized.',
    );

    await expect(
      serialize(payloadWithDot, [{ protectedHeader: unencodedProtectedHeader }], {
        jsonWebKeys: [jsonWebKey],
        detached: false,
      }),
    ).rejects.toThrowWithMessage(InvalidJsonWebSignatureError, 'The provided Unencoded Payload cannot be serialized.');
  });

  it('should serialize a General JSON Web Signature Protected Attached Unencoded Token without a dot.', async () => {
    await expect(
      serialize(payloadWithoutDot, [{ protectedHeader: unencodedProtectedHeader }], { jsonWebKeys: [jsonWebKey] }),
    ).resolves.toStrictEqual(unencodedProtectedAttachedTokenWithoutDot);
  });

  it('should serialize a General JSON Web Signature Protected and Unprotected Attached Unencoded Token without a dot.', async () => {
    await expect(
      serialize(payloadWithoutDot, [
        {
          protectedHeader: unencodedProtectedHeader,
          unprotectedHeader: {
            jwk: { ...jsonWebKey.parameters, kid: 'e9bc097a-ce51-4036-9562-d2ade882db0d' },
          },
        },
      ]),
    ).resolves.toStrictEqual<GeneralJsonWebSignatureToken>({
      payload: unencodedFullAttachedTokenWithoutDot.payload!,
      signatures: unencodedFullAttachedTokenWithoutDot.signatures.map((signature) => ({
        protected: signature.protected!,
        header: { jwk: { ...jsonWebKey.parameters, kid: 'e9bc097a-ce51-4036-9562-d2ade882db0d' } },
        signature: signature.signature,
      })),
    });
  });

  it('should serialize a General JSON Web Signature Protected Detached Unencoded Token without a dot.', async () => {
    await expect(
      serialize(payloadWithoutDot, [{ protectedHeader: unencodedProtectedHeader }], {
        jsonWebKeys: [jsonWebKey],
        detached: true,
      }),
    ).resolves.toStrictEqual(unencodedProtectedDetachedTokenWithoutDot);
  });

  it('should serialize a General JSON Web Signature Protected and Unprotected Detached Unencoded Token without a dot.', async () => {
    await expect(
      serialize(payloadWithoutDot, [{ protectedHeader: unencodedProtectedHeader, unprotectedHeader }], {
        jsonWebKeys: [jsonWebKey],
        detached: true,
      }),
    ).resolves.toStrictEqual(unencodedFullDetachedTokenWithoutDot);
  });

  it('should serialize a General JSON Web Signature Protected Detached Unencoded Token with a dot.', async () => {
    await expect(
      serialize(payloadWithDot, [{ protectedHeader: unencodedProtectedHeader }], {
        jsonWebKeys: [jsonWebKey],
        detached: true,
      }),
    ).resolves.toStrictEqual(unencodedProtectedDetachedTokenWithDot);
  });

  it('should serialize a General JSON Web Signature Protected and Unprotected Detached Unencoded Token with a dot.', async () => {
    await expect(
      serialize(payloadWithDot, [{ protectedHeader: unencodedProtectedHeader, unprotectedHeader }], {
        jsonWebKeys: [jsonWebKey],
        detached: true,
      }),
    ).resolves.toStrictEqual(unencodedFullDetachedTokenWithDot);
  });

  it('should serialize a General JSON Web Signature Protected Attached Encoded Token without a dot.', async () => {
    await expect(
      serialize(payloadWithoutDot, [{ protectedHeader: encodedProtectedHeader }], { jsonWebKeys: [jsonWebKey] }),
    ).resolves.toStrictEqual(encodedProtectedAttachedToken);
  });

  it('should serialize a General JSON Web Signature Unprotected Attached Encoded Token without a dot.', async () => {
    await expect(
      serialize(payloadWithoutDot, [{ unprotectedHeader: { ...encodedProtectedHeader, ...unprotectedHeader } }], {
        jsonWebKeys: [jsonWebKey],
      }),
    ).resolves.toStrictEqual(encodedUnprotectedAttachedToken);
  });

  it('should serialize a General JSON Web Signature Protected and Unprotected Attached Encoded Token without a dot.', async () => {
    await expect(
      serialize(payloadWithoutDot, [{ protectedHeader: encodedProtectedHeader, unprotectedHeader }], {
        jsonWebKeys: [jsonWebKey],
      }),
    ).resolves.toStrictEqual(encodedFullAttachedToken);
  });

  it('should serialize a General JSON Web Signature Protected Detached Encoded Token without a dot.', async () => {
    await expect(
      serialize(payloadWithoutDot, [{ protectedHeader: encodedProtectedHeader }], {
        jsonWebKeys: [jsonWebKey],
        detached: true,
      }),
    ).resolves.toStrictEqual(encodedProtectedDetachedToken);
  });

  it('should serialize a General JSON Web Signature Unprotected Detached Encoded Token without a dot.', async () => {
    await expect(
      serialize(payloadWithoutDot, [{ unprotectedHeader: { ...encodedProtectedHeader, ...unprotectedHeader } }], {
        jsonWebKeys: [jsonWebKey],
        detached: true,
      }),
    ).resolves.toStrictEqual(encodedUnprotectedDetachedToken);
  });

  it('should serialize a General JSON Web Signature Protected and Unprotected Detached Encoded Token without a dot.', async () => {
    await expect(
      serialize(payloadWithoutDot, [{ protectedHeader: encodedProtectedHeader, unprotectedHeader }], {
        jsonWebKeys: [jsonWebKey],
        detached: true,
      }),
    ).resolves.toStrictEqual(encodedFullDetachedToken);
  });
});
