import { Buffer } from 'buffer';

import { InvalidJsonWebSignatureError } from '../../../errors/invalid-jsonwebsignature.error';
import { OctetSequenceJsonWebKey } from '../../../jwa/jwk/oct/octet-sequence.jsonwebkey';
import { JsonWebSignatureHeader } from '../../jsonwebsignature-header';
import { JsonWebSignatureHeaderParameters } from '../../jsonwebsignature-header.parameters';
import { deserialize } from './deserialize';
import { GeneralJsonWebSignature } from './general-jsonwebsignature';
import { GeneralJsonWebSignatureToken } from './general-jsonwebsignature.token';
import { GeneralJsonWebSignatureParsedHeaders } from './general-jsonwebsignature-parsed-headers';

const invalidTokens: any[] = [undefined, null, true, 1, 1.2, 1n, '', Symbol('a'), Buffer, Buffer.alloc(1), () => 1, []];

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

const invalidSignatures: any[] = [
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
  [() => 1],
  [[]],
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
  ['A128KW'],
];

describe('deserialize()', () => {
  const wrongSignatureToken: GeneralJsonWebSignatureToken = {
    payload: '{"iat": 1723010455, "sub": "078BWDDXasdcg8"}',
    signatures: [
      {
        protected: 'eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19',
        signature: 'oYyAwnx7D5WIo3L1WWx_zBSNX12nH8lwXQHgpPiApSk',
      },
    ],
  };

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

  const missingUnencodedProtectedAttachedTokenWithoutDot: GeneralJsonWebSignatureToken = {
    payload: '{"iat": 1723010455, "sub": "078BWDDXasdcg8"}',
    signatures: [{ protected: 'eyJhbGciOiJIUzI1NiJ9', signature: 'uXQJV7FqjHNukDJPwTa4wtywtIoQ9CiBf16ETgFeKjA' }],
  };

  const badUnencodedUnprotectedAttachedTokenWithoutDot: GeneralJsonWebSignatureToken = {
    payload: '{"iat": 1723010455, "sub": "078BWDDXasdcg8"}',
    signatures: [
      {
        header: { alg: 'HS256', b64: false, crit: ['b64'], kid: 'e9bc097a-ce51-4036-9562-d2ade882db0d' },
        signature: 'uXQJV7FqjHNukDJPwTa4wtywtIoQ9CiBf16ETgFeKjA',
      },
    ],
  };

  const missingUnencodedUnprotectedAttachedTokenWithoutDot: GeneralJsonWebSignatureToken = {
    payload: '{"iat": 1723010455, "sub": "078BWDDXasdcg8"}',
    signatures: [
      {
        header: { alg: 'HS256', kid: 'e9bc097a-ce51-4036-9562-d2ade882db0d' },
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

  const badUnencodedFullAttachedTokenWithoutDot: GeneralJsonWebSignatureToken = {
    payload: '{"iat": 1723010455, "sub": "078BWDDXasdcg8"}',
    signatures: [
      {
        protected: 'eyJhbGciOiJIUzI1NiJ9',
        header: { b64: false, crit: ['b64'], kid: 'e9bc097a-ce51-4036-9562-d2ade882db0d' },
        signature: 'uXQJV7FqjHNukDJPwTa4wtywtIoQ9CiBf16ETgFeKjA',
      },
    ],
  };

  const missingUnencodedFullAttachedTokenWithoutDot: GeneralJsonWebSignatureToken = {
    payload: '{"iat": 1723010455, "sub": "078BWDDXasdcg8"}',
    signatures: [
      {
        protected: 'eyJhbGciOiJIUzI1NiJ9',
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

  const missingUnencodedProtectedDetachedTokenWithoutDot: GeneralJsonWebSignatureToken = {
    signatures: [{ protected: 'eyJhbGciOiJIUzI1NiJ9', signature: 'uXQJV7FqjHNukDJPwTa4wtywtIoQ9CiBf16ETgFeKjA' }],
  };

  const badUnencodedUnprotectedDetachedTokenWithoutDot: GeneralJsonWebSignatureToken = {
    signatures: [
      {
        header: { alg: 'HS256', b64: false, crit: ['b64'], kid: 'e9bc097a-ce51-4036-9562-d2ade882db0d' },
        signature: 'uXQJV7FqjHNukDJPwTa4wtywtIoQ9CiBf16ETgFeKjA',
      },
    ],
  };

  const missingUnencodedUnprotectedDetachedTokenWithoutDot: GeneralJsonWebSignatureToken = {
    signatures: [
      {
        header: { alg: 'HS256', kid: 'e9bc097a-ce51-4036-9562-d2ade882db0d' },
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

  const badUnencodedFullDetachedTokenWithoutDot: GeneralJsonWebSignatureToken = {
    signatures: [
      {
        protected: 'eyJhbGciOiJIUzI1NiJ9',
        header: { b64: false, crit: ['b64'], kid: 'e9bc097a-ce51-4036-9562-d2ade882db0d' },
        signature: 'uXQJV7FqjHNukDJPwTa4wtywtIoQ9CiBf16ETgFeKjA',
      },
    ],
  };

  const missingUnencodedFullDetachedTokenWithoutDot: GeneralJsonWebSignatureToken = {
    signatures: [
      {
        protected: 'eyJhbGciOiJIUzI1NiJ9',
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

  const missingUnencodedProtectedDetachedTokenWithDot: GeneralJsonWebSignatureToken = {
    signatures: [{ protected: 'eyJhbGciOiJIUzI1NiJ9', signature: 'Tb6KReuvHIM29TcHMTRZwMJAAs5zuCSX4gTMSplXjEs' }],
  };

  const badUnencodedUnprotectedDetachedTokenWithDot: GeneralJsonWebSignatureToken = {
    signatures: [
      {
        header: { alg: 'HS256', b64: false, crit: ['b64'], kid: 'e9bc097a-ce51-4036-9562-d2ade882db0d' },
        signature: 'Tb6KReuvHIM29TcHMTRZwMJAAs5zuCSX4gTMSplXjEs',
      },
    ],
  };

  const missingUnencodedUnprotectedDetachedTokenWithDot: GeneralJsonWebSignatureToken = {
    signatures: [
      {
        header: { alg: 'HS256', kid: 'e9bc097a-ce51-4036-9562-d2ade882db0d' },
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

  const badUnencodedFullDetachedTokenWithDot: GeneralJsonWebSignatureToken = {
    signatures: [
      {
        protected: 'eyJhbGciOiJIUzI1NiJ9',
        header: { b64: false, crit: ['b64'], kid: 'e9bc097a-ce51-4036-9562-d2ade882db0d' },
        signature: 'Tb6KReuvHIM29TcHMTRZwMJAAs5zuCSX4gTMSplXjEs',
      },
    ],
  };

  const missingUnencodedFullDetachedTokenWithDot: GeneralJsonWebSignatureToken = {
    signatures: [
      {
        protected: 'eyJhbGciOiJIUzI1NiJ9',
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

  it.each(invalidTokens)(
    'should throw when the provided General JSON Web Signature Token is invalid.',
    async (token) => {
      await expect(deserialize(token)).rejects.toThrowWithMessage(
        TypeError,
        'The provided General JSON Web Signature Token is invalid.',
      );
    },
  );

  it.each(invalidDeserializeOptions)('should throw when the provided options is invalid.', async (options) => {
    await expect(deserialize(unencodedProtectedAttachedTokenWithoutDot, options)).rejects.toThrowWithMessage(
      TypeError,
      'The provided options is invalid.',
    );
  });

  it.each(invalidDetachedPayloads)(
    'should throw when the provided option "detachedPayload" is invalid.',
    async (detachedPayload) => {
      await expect(
        deserialize(unencodedProtectedAttachedTokenWithoutDot, { detachedPayload }),
      ).rejects.toThrowWithMessage(TypeError, 'The provided option "detachedPayload" is invalid.');
    },
  );

  it.each(invalidSignatures)('should throw when the provided option "signatures" is invalid.', async (signatures) => {
    await expect(deserialize(unencodedProtectedAttachedTokenWithoutDot, { signatures })).rejects.toThrowWithMessage(
      TypeError,
      'The provided option "signatures" is invalid.',
    );
  });

  it.each(invalidJsonWebKeys)(
    'should throw when the provided signature option "jsonWebKey" is invalid.',
    async (jsonWebKey) => {
      await expect(
        deserialize(unencodedProtectedAttachedTokenWithoutDot, { signatures: [{ jsonWebKey }] }),
      ).rejects.toThrowWithMessage(TypeError, 'The provided signature option "jsonWebKey" is invalid.');
    },
  );

  it.each(invalidExpectedAlgorithms)(
    'should throw when the provided signature option "expectedDigitalSignatureAlgorithms" is invalid.',
    async (expectedDigitalSignatureAlgorithms) => {
      await expect(
        deserialize(unencodedProtectedAttachedTokenWithoutDot, {
          signatures: [{ expectedDigitalSignatureAlgorithms }],
        }),
      ).rejects.toThrowWithMessage(
        TypeError,
        'The provided signature option "expectedDigitalSignatureAlgorithms" is invalid.',
      );
    },
  );

  it('should throw when the option "signatures" has length different than the signatures of the General JSON Web Signature Token.', async () => {
    await expect(
      deserialize(unencodedProtectedAttachedTokenWithoutDot, {
        signatures: [{ jsonWebKey }, { jsonWebKey }],
      }),
    ).rejects.toThrowWithMessage(
      TypeError,
      'The length of the option "signatures" and the General JSON Web Signature Token Signatures do not match.',
    );
  });

  it('should throw when deserializing a Detached General JSON Web Signature Token and not providing a Detached Payload.', async () => {
    await expect(deserialize(unencodedProtectedDetachedTokenWithoutDot)).rejects.toThrowWithMessage(
      InvalidJsonWebSignatureError,
      'The JSON Web Signature requires a valid Payload.',
    );
  });

  it('should throw when providing a Detached Payload for a General JSON Web Signature Token that already has a Payload.', async () => {
    await expect(
      deserialize(unencodedProtectedAttachedTokenWithoutDot, { detachedPayload: payloadWithoutDot }),
    ).rejects.toThrowWithMessage(
      InvalidJsonWebSignatureError,
      'The provided JSON Web Signature already has a defined Payload.',
    );
  });

  it('should throw when the JSON Web Signature Digital Signature Algorithm of the General JSON Web Signature Token is unexpected.', async () => {
    await expect(
      deserialize(unencodedProtectedAttachedTokenWithoutDot, {
        signatures: [{ expectedDigitalSignatureAlgorithms: ['HS512'] }],
      }),
    ).rejects.toThrowWithMessage(
      InvalidJsonWebSignatureError,
      'Unexpected JSON Web Signature Digital Signature Algorithm "HS256".',
    );
  });

  it('should throw when the provided Signature fails to deserialize the provided General JSON Web Signature Token.', async () => {
    await expect(deserialize(wrongSignatureToken)).rejects.toThrow();
  });

  it('should return the deserialized General JSON Web Signature from an Unencoded Protected Attached Token without a dot.', async () => {
    let jsonWebSignature!: GeneralJsonWebSignature;

    await expect(async () => {
      jsonWebSignature = await deserialize(unencodedProtectedAttachedTokenWithoutDot, {
        signatures: [{ jsonWebKey }],
      });
    }).resolves.not.toThrow();

    expect(jsonWebSignature.payload).toStrictEqual(payloadWithoutDot);

    expect(jsonWebSignature.headers).toBeInstanceOf(Array);
    expect(jsonWebSignature.headers).toSatisfyAll<GeneralJsonWebSignatureParsedHeaders>(
      (headers) => headers.header instanceof JsonWebSignatureHeader,
    );

    expect(jsonWebSignature.headers[0]!.header.parameters).toStrictEqual(unencodedProtectedHeader);

    expect(jsonWebSignature.headers[0]!.protectedHeader).toStrictEqual(unencodedProtectedHeader);
    expect(jsonWebSignature.headers[0]!.unprotectedHeader).toBeUndefined();
  });

  it('should throw when deserializing a General JSON Web Signature from an Unencoded Protected Attached Token without a dot that is missing the JOSE Header Parameter "b64".', async () => {
    await expect(
      deserialize(missingUnencodedProtectedAttachedTokenWithoutDot, {
        signatures: [{ jsonWebKey }],
      }),
    ).rejects.toThrowWithMessage(InvalidJsonWebSignatureError, 'The provided JSON Web Signature is invalid.');
  });

  it('should throw when deserializing a General JSON Web Signature from an Unencoded Unprotected Attached Token without a dot.', async () => {
    await expect(
      deserialize(badUnencodedUnprotectedAttachedTokenWithoutDot, { signatures: [{ jsonWebKey }] }),
    ).rejects.toThrowWithMessage(InvalidJsonWebSignatureError, 'The provided JSON Web Signature is invalid.');
  });

  it('should throw when deserializing a General JSON Web Signature from an Unencoded Unprotected Attached Token without a dot that is missing the JOSE Header Parameter "b64".', async () => {
    await expect(
      deserialize(missingUnencodedUnprotectedAttachedTokenWithoutDot, {
        signatures: [{ jsonWebKey }],
      }),
    ).rejects.toThrowWithMessage(InvalidJsonWebSignatureError, 'The provided JSON Web Signature is invalid.');
  });

  it('should return the deserialized General JSON Web Signature from an Unencoded Protected and Unprotected Attached Token without a dot.', async () => {
    let jsonWebSignature!: GeneralJsonWebSignature;

    await expect(async () => {
      jsonWebSignature = await deserialize(unencodedFullAttachedTokenWithoutDot, {
        signatures: [{ jsonWebKey }],
      });
    }).resolves.not.toThrow();

    expect(jsonWebSignature.payload).toStrictEqual(payloadWithoutDot);

    expect(jsonWebSignature.headers).toBeInstanceOf(Array);
    expect(jsonWebSignature.headers).toSatisfyAll<GeneralJsonWebSignatureParsedHeaders>(
      (headers) => headers.header instanceof JsonWebSignatureHeader,
    );

    expect(jsonWebSignature.headers[0]!.header.parameters).toStrictEqual<Partial<JsonWebSignatureHeaderParameters>>({
      ...unencodedProtectedHeader,
      ...unprotectedHeader,
    });

    expect(jsonWebSignature.headers[0]!.protectedHeader).toStrictEqual(unencodedProtectedHeader);
    expect(jsonWebSignature.headers[0]!.unprotectedHeader).toStrictEqual(unprotectedHeader);
  });

  it('should throw when deserializing a General JSON Web Signature from an Unencoded Protected and Unprotected Attached Token without a dot.', async () => {
    await expect(
      deserialize(badUnencodedFullAttachedTokenWithoutDot, { signatures: [{ jsonWebKey }] }),
    ).rejects.toThrowWithMessage(InvalidJsonWebSignatureError, 'The provided JSON Web Signature is invalid.');
  });

  it('should throw when deserializing a General JSON Web Signature from an Unencoded Protected and Unprotected Attached Token without a dot that is missing the JOSE Header Parameter "b64".', async () => {
    await expect(
      deserialize(missingUnencodedFullAttachedTokenWithoutDot, { signatures: [{ jsonWebKey }] }),
    ).rejects.toThrowWithMessage(InvalidJsonWebSignatureError, 'The provided JSON Web Signature is invalid.');
  });

  it('should return the deserialized General JSON Web Signature from an Unencoded Protected Detached Token without a dot.', async () => {
    let jsonWebSignature!: GeneralJsonWebSignature;

    await expect(async () => {
      jsonWebSignature = await deserialize(unencodedProtectedDetachedTokenWithoutDot, {
        detachedPayload: payloadWithoutDot,
        signatures: [{ jsonWebKey }],
      });
    }).resolves.not.toThrow();

    expect(jsonWebSignature.payload).toStrictEqual(payloadWithoutDot);

    expect(jsonWebSignature.headers).toBeInstanceOf(Array);
    expect(jsonWebSignature.headers).toSatisfyAll<GeneralJsonWebSignatureParsedHeaders>(
      (headers) => headers.header instanceof JsonWebSignatureHeader,
    );

    expect(jsonWebSignature.headers[0]!.header.parameters).toStrictEqual(unencodedProtectedHeader);

    expect(jsonWebSignature.headers[0]!.protectedHeader).toStrictEqual(unencodedProtectedHeader);
    expect(jsonWebSignature.headers[0]!.unprotectedHeader).toBeUndefined();
  });

  it('should throw when deserializing a General JSON Web Signature from an Unencoded Protected Detached Token without a dot that is missing the JOSE Header Parameter "b64".', async () => {
    await expect(
      deserialize(missingUnencodedProtectedDetachedTokenWithoutDot, {
        detachedPayload: payloadWithoutDot,
        signatures: [{ jsonWebKey }],
      }),
    ).rejects.toThrowWithMessage(InvalidJsonWebSignatureError, 'The provided JSON Web Signature is invalid.');
  });

  it('should throw when deserializing a General JSON Web Signature from an Unencoded Unprotected Detached Token without a dot.', async () => {
    await expect(
      deserialize(badUnencodedUnprotectedDetachedTokenWithoutDot, {
        detachedPayload: payloadWithoutDot,
        signatures: [{ jsonWebKey }],
      }),
    ).rejects.toThrowWithMessage(InvalidJsonWebSignatureError, 'The provided JSON Web Signature is invalid.');
  });

  it('should throw when deserializing a General JSON Web Signature from an Unencoded Unprotected Detached Token without a dot that is missing the JOSE Header Parameter "b64".', async () => {
    await expect(
      deserialize(missingUnencodedUnprotectedDetachedTokenWithoutDot, {
        detachedPayload: payloadWithoutDot,
        signatures: [{ jsonWebKey }],
      }),
    ).rejects.toThrowWithMessage(InvalidJsonWebSignatureError, 'The provided JSON Web Signature is invalid.');
  });

  it('should return the deserialized General JSON Web Signature from an Unencoded Protected and Unprotected Detached Token without a dot.', async () => {
    let jsonWebSignature!: GeneralJsonWebSignature;

    await expect(async () => {
      jsonWebSignature = await deserialize(unencodedFullDetachedTokenWithoutDot, {
        detachedPayload: payloadWithoutDot,
        signatures: [{ jsonWebKey }],
      });
    }).resolves.not.toThrow();

    expect(jsonWebSignature.payload).toStrictEqual(payloadWithoutDot);

    expect(jsonWebSignature.headers).toBeInstanceOf(Array);
    expect(jsonWebSignature.headers).toSatisfyAll<GeneralJsonWebSignatureParsedHeaders>(
      (headers) => headers.header instanceof JsonWebSignatureHeader,
    );

    expect(jsonWebSignature.headers[0]!.header.parameters).toStrictEqual<Partial<JsonWebSignatureHeaderParameters>>({
      ...unencodedProtectedHeader,
      ...unprotectedHeader,
    });

    expect(jsonWebSignature.headers[0]!.protectedHeader).toStrictEqual(unencodedProtectedHeader);
    expect(jsonWebSignature.headers[0]!.unprotectedHeader).toStrictEqual(unprotectedHeader);
  });

  it('should throw when deserializing a General JSON Web Signature from an Unencoded Protected and Unprotected Detached Token without a dot.', async () => {
    await expect(
      deserialize(badUnencodedFullDetachedTokenWithoutDot, {
        detachedPayload: payloadWithoutDot,
        signatures: [{ jsonWebKey }],
      }),
    ).rejects.toThrowWithMessage(InvalidJsonWebSignatureError, 'The provided JSON Web Signature is invalid.');
  });

  it('should throw when deserializing a General JSON Web Signature from an Unencoded Protected and Unprotected Detached Token without a dot that is missing the JOSE Header Parameter "b64".', async () => {
    await expect(
      deserialize(missingUnencodedFullDetachedTokenWithoutDot, {
        detachedPayload: payloadWithoutDot,
        signatures: [{ jsonWebKey }],
      }),
    ).rejects.toThrowWithMessage(InvalidJsonWebSignatureError, 'The provided JSON Web Signature is invalid.');
  });

  it('should return the deserialized General JSON Web Signature from an Unencoded Protected Detached Token with a dot.', async () => {
    let jsonWebSignature!: GeneralJsonWebSignature;

    await expect(async () => {
      jsonWebSignature = await deserialize(unencodedProtectedDetachedTokenWithDot, {
        detachedPayload: payloadWithDot,
        signatures: [{ jsonWebKey }],
      });
    }).resolves.not.toThrow();

    expect(jsonWebSignature.payload).toStrictEqual(payloadWithDot);

    expect(jsonWebSignature.headers).toBeInstanceOf(Array);
    expect(jsonWebSignature.headers).toSatisfyAll<GeneralJsonWebSignatureParsedHeaders>(
      (headers) => headers.header instanceof JsonWebSignatureHeader,
    );

    expect(jsonWebSignature.headers[0]!.header.parameters).toStrictEqual(unencodedProtectedHeader);

    expect(jsonWebSignature.headers[0]!.protectedHeader).toStrictEqual(unencodedProtectedHeader);
    expect(jsonWebSignature.headers[0]!.unprotectedHeader).toBeUndefined();
  });

  it('should throw when deserializing a General JSON Web Signature from an Unencoded Protected Detached Token with a dot that is missing the JOSE Header Parameter "b64".', async () => {
    await expect(
      deserialize(missingUnencodedProtectedDetachedTokenWithDot, {
        detachedPayload: payloadWithDot,
        signatures: [{ jsonWebKey }],
      }),
    ).rejects.toThrowWithMessage(InvalidJsonWebSignatureError, 'The provided JSON Web Signature is invalid.');
  });

  it('should throw when deserializing a General JSON Web Signature from an Unencoded Unprotected Detached Token with a dot.', async () => {
    await expect(
      deserialize(badUnencodedUnprotectedDetachedTokenWithDot, {
        detachedPayload: payloadWithDot,
        signatures: [{ jsonWebKey }],
      }),
    ).rejects.toThrowWithMessage(InvalidJsonWebSignatureError, 'The provided JSON Web Signature is invalid.');
  });

  it('should throw when deserializing a General JSON Web Signature from an Unencoded Unprotected Detached Token with a dot that is missing the JOSE Header Parameter "b64".', async () => {
    await expect(
      deserialize(missingUnencodedUnprotectedDetachedTokenWithDot, {
        detachedPayload: payloadWithDot,
        signatures: [{ jsonWebKey }],
      }),
    ).rejects.toThrowWithMessage(InvalidJsonWebSignatureError, 'The provided JSON Web Signature is invalid.');
  });

  it('should return the deserialized General JSON Web Signature from an Unencoded Protected and Unprotected Detached Token with a dot.', async () => {
    let jsonWebSignature!: GeneralJsonWebSignature;

    await expect(async () => {
      jsonWebSignature = await deserialize(unencodedFullDetachedTokenWithDot, {
        detachedPayload: payloadWithDot,
        signatures: [{ jsonWebKey }],
      });
    }).resolves.not.toThrow();

    expect(jsonWebSignature.payload).toStrictEqual(payloadWithDot);

    expect(jsonWebSignature.headers).toBeInstanceOf(Array);
    expect(jsonWebSignature.headers).toSatisfyAll<GeneralJsonWebSignatureParsedHeaders>(
      (headers) => headers.header instanceof JsonWebSignatureHeader,
    );

    expect(jsonWebSignature.headers[0]!.header.parameters).toStrictEqual<Partial<JsonWebSignatureHeaderParameters>>({
      ...unencodedProtectedHeader,
      ...unprotectedHeader,
    });

    expect(jsonWebSignature.headers[0]!.protectedHeader).toStrictEqual(unencodedProtectedHeader);
    expect(jsonWebSignature.headers[0]!.unprotectedHeader).toStrictEqual(unprotectedHeader);
  });

  it('should throw when deserializing a General JSON Web Signature from an Unencoded Protected and Unprotected Detached Token with a dot.', async () => {
    await expect(
      deserialize(badUnencodedFullDetachedTokenWithDot, {
        detachedPayload: payloadWithDot,
        signatures: [{ jsonWebKey }],
      }),
    ).rejects.toThrowWithMessage(InvalidJsonWebSignatureError, 'The provided JSON Web Signature is invalid.');
  });

  it('should throw when deserializing a General JSON Web Signature from an Unencoded Protected and Unprotected Detached Token with a dot that is missing the JOSE Header Parameter "b64".', async () => {
    await expect(
      deserialize(missingUnencodedFullDetachedTokenWithDot, {
        detachedPayload: payloadWithDot,
        signatures: [{ jsonWebKey }],
      }),
    ).rejects.toThrowWithMessage(InvalidJsonWebSignatureError, 'The provided JSON Web Signature is invalid.');
  });

  it('should return the deserialized General JSON Web Signature from an Encoded Protected Attached Token without a dot.', async () => {
    let jsonWebSignature!: GeneralJsonWebSignature;

    await expect(async () => {
      jsonWebSignature = await deserialize(encodedProtectedAttachedToken, { signatures: [{ jsonWebKey }] });
    }).resolves.not.toThrow();

    expect(jsonWebSignature.payload).toStrictEqual(payloadWithoutDot);

    expect(jsonWebSignature.headers).toBeInstanceOf(Array);
    expect(jsonWebSignature.headers).toSatisfyAll<GeneralJsonWebSignatureParsedHeaders>(
      (headers) => headers.header instanceof JsonWebSignatureHeader,
    );

    expect(jsonWebSignature.headers[0]!.header.parameters).toStrictEqual(encodedProtectedHeader);

    expect(jsonWebSignature.headers[0]!.protectedHeader).toStrictEqual(encodedProtectedHeader);
    expect(jsonWebSignature.headers[0]!.unprotectedHeader).toBeUndefined();
  });

  it('should return the deserialized General JSON Web Signature from an Encoded Unprotected Attached Token without a dot.', async () => {
    let jsonWebSignature!: GeneralJsonWebSignature;

    await expect(async () => {
      jsonWebSignature = await deserialize(encodedUnprotectedAttachedToken, { signatures: [{ jsonWebKey }] });
    }).resolves.not.toThrow();

    expect(jsonWebSignature.payload).toStrictEqual(payloadWithoutDot);

    expect(jsonWebSignature.headers).toBeInstanceOf(Array);
    expect(jsonWebSignature.headers).toSatisfyAll<GeneralJsonWebSignatureParsedHeaders>(
      (headers) => headers.header instanceof JsonWebSignatureHeader,
    );

    expect(jsonWebSignature.headers[0]!.header.parameters).toStrictEqual<Partial<JsonWebSignatureHeaderParameters>>({
      ...encodedProtectedHeader,
      ...unprotectedHeader,
    });

    expect(jsonWebSignature.headers[0]!.protectedHeader).toBeUndefined();
    expect(jsonWebSignature.headers[0]!.unprotectedHeader).toStrictEqual<Partial<JsonWebSignatureHeaderParameters>>({
      ...encodedProtectedHeader,
      ...unprotectedHeader,
    });
  });

  it('should return the deserialized General JSON Web Signature from an Encoded Protected and Unprotected Attached Token without a dot.', async () => {
    let jsonWebSignature!: GeneralJsonWebSignature;

    await expect(async () => {
      jsonWebSignature = await deserialize(encodedFullAttachedToken, { signatures: [{ jsonWebKey }] });
    }).resolves.not.toThrow();

    expect(jsonWebSignature.payload).toStrictEqual(payloadWithoutDot);

    expect(jsonWebSignature.headers).toBeInstanceOf(Array);
    expect(jsonWebSignature.headers).toSatisfyAll<GeneralJsonWebSignatureParsedHeaders>(
      (headers) => headers.header instanceof JsonWebSignatureHeader,
    );

    expect(jsonWebSignature.headers[0]!.header.parameters).toStrictEqual<Partial<JsonWebSignatureHeaderParameters>>({
      ...encodedProtectedHeader,
      ...unprotectedHeader,
    });

    expect(jsonWebSignature.headers[0]!.protectedHeader).toStrictEqual(encodedProtectedHeader);
    expect(jsonWebSignature.headers[0]!.unprotectedHeader).toStrictEqual(unprotectedHeader);
  });

  it('should return the deserialized General JSON Web Signature from an Encoded Protected Detached Token without a dot.', async () => {
    let jsonWebSignature!: GeneralJsonWebSignature;

    await expect(async () => {
      jsonWebSignature = await deserialize(encodedProtectedDetachedToken, {
        detachedPayload: payloadWithoutDot,
        signatures: [{ jsonWebKey }],
      });
    }).resolves.not.toThrow();

    expect(jsonWebSignature.payload).toStrictEqual(payloadWithoutDot);

    expect(jsonWebSignature.headers).toBeInstanceOf(Array);
    expect(jsonWebSignature.headers).toSatisfyAll<GeneralJsonWebSignatureParsedHeaders>(
      (headers) => headers.header instanceof JsonWebSignatureHeader,
    );

    expect(jsonWebSignature.headers[0]!.header.parameters).toStrictEqual(encodedProtectedHeader);

    expect(jsonWebSignature.headers[0]!.protectedHeader).toStrictEqual(encodedProtectedHeader);
    expect(jsonWebSignature.headers[0]!.unprotectedHeader).toBeUndefined();
  });

  it('should return the deserialized General JSON Web Signature from an Encoded Unprotected Detached Token without a dot.', async () => {
    let jsonWebSignature!: GeneralJsonWebSignature;

    await expect(async () => {
      jsonWebSignature = await deserialize(encodedUnprotectedDetachedToken, {
        detachedPayload: payloadWithoutDot,
        signatures: [{ jsonWebKey }],
      });
    }).resolves.not.toThrow();

    expect(jsonWebSignature.payload).toStrictEqual(payloadWithoutDot);

    expect(jsonWebSignature.headers).toBeInstanceOf(Array);
    expect(jsonWebSignature.headers).toSatisfyAll<GeneralJsonWebSignatureParsedHeaders>(
      (headers) => headers.header instanceof JsonWebSignatureHeader,
    );

    expect(jsonWebSignature.headers[0]!.header.parameters).toStrictEqual<Partial<JsonWebSignatureHeaderParameters>>({
      ...encodedProtectedHeader,
      ...unprotectedHeader,
    });

    expect(jsonWebSignature.headers[0]!.protectedHeader).toBeUndefined();
    expect(jsonWebSignature.headers[0]!.unprotectedHeader).toStrictEqual<Partial<JsonWebSignatureHeaderParameters>>({
      ...encodedProtectedHeader,
      ...unprotectedHeader,
    });
  });

  it('should return the deserialized General JSON Web Signature from an Encoded Protected and Unprotected Detached Token without a dot.', async () => {
    let jsonWebSignature!: GeneralJsonWebSignature;

    await expect(async () => {
      jsonWebSignature = await deserialize(encodedFullDetachedToken, {
        detachedPayload: payloadWithoutDot,
        signatures: [{ jsonWebKey }],
      });
    }).resolves.not.toThrow();

    expect(jsonWebSignature.payload).toStrictEqual(payloadWithoutDot);

    expect(jsonWebSignature.headers).toBeInstanceOf(Array);
    expect(jsonWebSignature.headers).toSatisfyAll<GeneralJsonWebSignatureParsedHeaders>(
      (headers) => headers.header instanceof JsonWebSignatureHeader,
    );

    expect(jsonWebSignature.headers[0]!.header.parameters).toStrictEqual<Partial<JsonWebSignatureHeaderParameters>>({
      ...encodedProtectedHeader,
      ...unprotectedHeader,
    });

    expect(jsonWebSignature.headers[0]!.protectedHeader).toStrictEqual(encodedProtectedHeader);
    expect(jsonWebSignature.headers[0]!.unprotectedHeader).toStrictEqual(unprotectedHeader);
  });
});
