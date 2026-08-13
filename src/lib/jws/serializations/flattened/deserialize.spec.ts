import { Buffer } from 'buffer';

import { InvalidJsonWebSignatureError } from '../../../errors/invalid-jsonwebsignature.error';
import { OctetSequenceJsonWebKey } from '../../../jwa/jwk/oct/octet-sequence.jsonwebkey';
import { JsonWebSignatureHeader } from '../../jsonwebsignature-header';
import { JsonWebSignatureHeaderParameters } from '../../jsonwebsignature-header.parameters';
import { deserialize } from './deserialize';
import { FlattenedJsonWebSignature } from './flattened-jsonwebsignature';
import { FlattenedJsonWebSignatureToken } from './flattened-jsonwebsignature.token';

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
  ['A128KW'],
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

const invalidTokens: any[] = [undefined, null, true, 1, 1.2, 1n, '', Symbol('a'), Buffer, Buffer.alloc(1), () => 1, []];

describe('deserialize()', () => {
  const wrongSignatureToken: FlattenedJsonWebSignatureToken = {
    protected: 'eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19',
    payload: '{"iat": 1723010455, "sub": "078BWDDXasdcg8"}',
    signature: 'oYyAwnx7D5WIo3L1WWx_zBSNX12nH8lwXQHgpPiApSk',
  };

  // #region Unencoded Attached Token Without Dot
  const unencodedProtectedAttachedTokenWithoutDot: FlattenedJsonWebSignatureToken = {
    protected: 'eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19',
    payload: '{"iat": 1723010455, "sub": "078BWDDXasdcg8"}',
    signature: 'uXQJV7FqjHNukDJPwTa4wtywtIoQ9CiBf16ETgFeKjA',
  };

  const missingUnencodedProtectedAttachedTokenWithoutDot: FlattenedJsonWebSignatureToken = {
    protected: 'eyJhbGciOiJIUzI1NiJ9',
    payload: '{"iat": 1723010455, "sub": "078BWDDXasdcg8"}',
    signature: 'uXQJV7FqjHNukDJPwTa4wtywtIoQ9CiBf16ETgFeKjA',
  };

  const badUnencodedUnprotectedAttachedTokenWithoutDot: FlattenedJsonWebSignatureToken = {
    header: { alg: 'HS256', b64: false, crit: ['b64'], kid: 'e9bc097a-ce51-4036-9562-d2ade882db0d' },
    payload: '{"iat": 1723010455, "sub": "078BWDDXasdcg8"}',
    signature: 'uXQJV7FqjHNukDJPwTa4wtywtIoQ9CiBf16ETgFeKjA',
  };

  const missingUnencodedUnprotectedAttachedTokenWithoutDot: FlattenedJsonWebSignatureToken = {
    header: { alg: 'HS256', kid: 'e9bc097a-ce51-4036-9562-d2ade882db0d' },
    payload: '{"iat": 1723010455, "sub": "078BWDDXasdcg8"}',
    signature: 'uXQJV7FqjHNukDJPwTa4wtywtIoQ9CiBf16ETgFeKjA',
  };

  const unencodedFullAttachedTokenWithoutDot: FlattenedJsonWebSignatureToken = {
    protected: 'eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19',
    header: { kid: 'e9bc097a-ce51-4036-9562-d2ade882db0d' },
    payload: '{"iat": 1723010455, "sub": "078BWDDXasdcg8"}',
    signature: 'uXQJV7FqjHNukDJPwTa4wtywtIoQ9CiBf16ETgFeKjA',
  };

  const badUnencodedFullAttachedTokenWithoutDot: FlattenedJsonWebSignatureToken = {
    protected: 'eyJhbGciOiJIUzI1NiJ9',
    header: { b64: false, crit: ['b64'], kid: 'e9bc097a-ce51-4036-9562-d2ade882db0d' },
    payload: '{"iat": 1723010455, "sub": "078BWDDXasdcg8"}',
    signature: 'uXQJV7FqjHNukDJPwTa4wtywtIoQ9CiBf16ETgFeKjA',
  };

  const missingUnencodedFullAttachedTokenWithoutDot: FlattenedJsonWebSignatureToken = {
    protected: 'eyJhbGciOiJIUzI1NiJ9',
    header: { kid: 'e9bc097a-ce51-4036-9562-d2ade882db0d' },
    payload: '{"iat": 1723010455, "sub": "078BWDDXasdcg8"}',
    signature: 'uXQJV7FqjHNukDJPwTa4wtywtIoQ9CiBf16ETgFeKjA',
  };
  // #endregion
  // #region Unencoded Detached Token Without Dot
  const unencodedProtectedDetachedTokenWithoutDot: FlattenedJsonWebSignatureToken = {
    protected: 'eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19',
    signature: 'uXQJV7FqjHNukDJPwTa4wtywtIoQ9CiBf16ETgFeKjA',
  };

  const missingUnencodedProtectedDetachedTokenWithoutDot: FlattenedJsonWebSignatureToken = {
    protected: 'eyJhbGciOiJIUzI1NiJ9',
    signature: 'uXQJV7FqjHNukDJPwTa4wtywtIoQ9CiBf16ETgFeKjA',
  };

  const badUnencodedUnprotectedDetachedTokenWithoutDot: FlattenedJsonWebSignatureToken = {
    header: { alg: 'HS256', b64: false, crit: ['b64'], kid: 'e9bc097a-ce51-4036-9562-d2ade882db0d' },
    signature: 'uXQJV7FqjHNukDJPwTa4wtywtIoQ9CiBf16ETgFeKjA',
  };

  const missingUnencodedUnprotectedDetachedTokenWithoutDot: FlattenedJsonWebSignatureToken = {
    header: { alg: 'HS256', kid: 'e9bc097a-ce51-4036-9562-d2ade882db0d' },
    signature: 'uXQJV7FqjHNukDJPwTa4wtywtIoQ9CiBf16ETgFeKjA',
  };

  const unencodedFullDetachedTokenWithoutDot: FlattenedJsonWebSignatureToken = {
    protected: 'eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19',
    header: { kid: 'e9bc097a-ce51-4036-9562-d2ade882db0d' },
    signature: 'uXQJV7FqjHNukDJPwTa4wtywtIoQ9CiBf16ETgFeKjA',
  };

  const badUnencodedFullDetachedTokenWithoutDot: FlattenedJsonWebSignatureToken = {
    protected: 'eyJhbGciOiJIUzI1NiJ9',
    header: { b64: false, crit: ['b64'], kid: 'e9bc097a-ce51-4036-9562-d2ade882db0d' },
    signature: 'uXQJV7FqjHNukDJPwTa4wtywtIoQ9CiBf16ETgFeKjA',
  };

  const missingUnencodedFullDetachedTokenWithoutDot: FlattenedJsonWebSignatureToken = {
    protected: 'eyJhbGciOiJIUzI1NiJ9',
    header: { kid: 'e9bc097a-ce51-4036-9562-d2ade882db0d' },
    signature: 'uXQJV7FqjHNukDJPwTa4wtywtIoQ9CiBf16ETgFeKjA',
  };
  // #endregion
  // #region Unencoded Detached Token With Dot
  const unencodedProtectedDetachedTokenWithDot: FlattenedJsonWebSignatureToken = {
    protected: 'eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19',
    signature: 'Tb6KReuvHIM29TcHMTRZwMJAAs5zuCSX4gTMSplXjEs',
  };

  const missingUnencodedProtectedDetachedTokenWithDot: FlattenedJsonWebSignatureToken = {
    protected: 'eyJhbGciOiJIUzI1NiJ9',
    signature: 'Tb6KReuvHIM29TcHMTRZwMJAAs5zuCSX4gTMSplXjEs',
  };

  const badUnencodedUnprotectedDetachedTokenWithDot: FlattenedJsonWebSignatureToken = {
    header: { alg: 'HS256', b64: false, crit: ['b64'], kid: 'e9bc097a-ce51-4036-9562-d2ade882db0d' },
    signature: 'Tb6KReuvHIM29TcHMTRZwMJAAs5zuCSX4gTMSplXjEs',
  };

  const missingUnencodedUnprotectedDetachedTokenWithDot: FlattenedJsonWebSignatureToken = {
    header: { alg: 'HS256', kid: 'e9bc097a-ce51-4036-9562-d2ade882db0d' },
    signature: 'Tb6KReuvHIM29TcHMTRZwMJAAs5zuCSX4gTMSplXjEs',
  };

  const unencodedFullDetachedTokenWithDot: FlattenedJsonWebSignatureToken = {
    protected: 'eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19',
    header: { kid: 'e9bc097a-ce51-4036-9562-d2ade882db0d' },
    signature: 'Tb6KReuvHIM29TcHMTRZwMJAAs5zuCSX4gTMSplXjEs',
  };

  const badUnencodedFullDetachedTokenWithDot: FlattenedJsonWebSignatureToken = {
    protected: 'eyJhbGciOiJIUzI1NiJ9',
    header: { b64: false, crit: ['b64'], kid: 'e9bc097a-ce51-4036-9562-d2ade882db0d' },
    signature: 'Tb6KReuvHIM29TcHMTRZwMJAAs5zuCSX4gTMSplXjEs',
  };

  const missingUnencodedFullDetachedTokenWithDot: FlattenedJsonWebSignatureToken = {
    protected: 'eyJhbGciOiJIUzI1NiJ9',
    header: { kid: 'e9bc097a-ce51-4036-9562-d2ade882db0d' },
    signature: 'Tb6KReuvHIM29TcHMTRZwMJAAs5zuCSX4gTMSplXjEs',
  };
  // #endregion
  // #region Encoded Attached Token
  const encodedProtectedAttachedToken: FlattenedJsonWebSignatureToken = {
    protected: 'eyJhbGciOiJIUzI1NiJ9',
    payload: 'eyJpYXQiOiAxNzIzMDEwNDU1LCAic3ViIjogIjA3OEJXRERYYXNkY2c4In0',
    signature: 'hRqmKz7sKWQZyNM1Kw9AgqPNOedszPvEADYmNFo8foA',
  };

  const encodedUnprotectedAttachedToken: FlattenedJsonWebSignatureToken = {
    header: { alg: 'HS256', kid: 'e9bc097a-ce51-4036-9562-d2ade882db0d' },
    payload: 'eyJpYXQiOiAxNzIzMDEwNDU1LCAic3ViIjogIjA3OEJXRERYYXNkY2c4In0',
    signature: 'iRxcRLDYSMrd3ZlYZ_tUXP8pRAShmoErGTo4sEsew3U',
  };

  const encodedFullAttachedToken: FlattenedJsonWebSignatureToken = {
    protected: 'eyJhbGciOiJIUzI1NiJ9',
    header: { kid: 'e9bc097a-ce51-4036-9562-d2ade882db0d' },
    payload: 'eyJpYXQiOiAxNzIzMDEwNDU1LCAic3ViIjogIjA3OEJXRERYYXNkY2c4In0',
    signature: 'hRqmKz7sKWQZyNM1Kw9AgqPNOedszPvEADYmNFo8foA',
  };
  // #endregion
  // #region Encoded Detached Token
  const encodedProtectedDetachedToken: FlattenedJsonWebSignatureToken = {
    protected: 'eyJhbGciOiJIUzI1NiJ9',
    signature: 'hRqmKz7sKWQZyNM1Kw9AgqPNOedszPvEADYmNFo8foA',
  };

  const encodedUnprotectedDetachedToken: FlattenedJsonWebSignatureToken = {
    header: { alg: 'HS256', kid: 'e9bc097a-ce51-4036-9562-d2ade882db0d' },
    signature: 'iRxcRLDYSMrd3ZlYZ_tUXP8pRAShmoErGTo4sEsew3U',
  };

  const encodedFullDetachedToken: FlattenedJsonWebSignatureToken = {
    protected: 'eyJhbGciOiJIUzI1NiJ9',
    header: { kid: 'e9bc097a-ce51-4036-9562-d2ade882db0d' },
    signature: 'hRqmKz7sKWQZyNM1Kw9AgqPNOedszPvEADYmNFo8foA',
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

  it.each(invalidDeserializeOptions)('should throw when the provided options is invalid.', async (options) => {
    await expect(deserialize(unencodedProtectedAttachedTokenWithoutDot, options)).rejects.toThrowWithMessage(
      TypeError,
      'The provided options is invalid.',
    );
  });

  it.each(invalidJsonWebKeys)('should throw when the provided option "jsonWebKey" is invalid.', async (jsonWebKey) => {
    await expect(deserialize(unencodedProtectedAttachedTokenWithoutDot, { jsonWebKey })).rejects.toThrowWithMessage(
      TypeError,
      'The provided option "jsonWebKey" is invalid.',
    );
  });

  it.each(invalidExpectedAlgorithms)(
    'should throw when the provided option "expectedDigitalSignatureAlgorithms" is invalid.',
    async (expectedDigitalSignatureAlgorithms) => {
      await expect(
        deserialize(unencodedProtectedAttachedTokenWithoutDot, { expectedDigitalSignatureAlgorithms }),
      ).rejects.toThrowWithMessage(TypeError, 'The provided option "expectedDigitalSignatureAlgorithms" is invalid.');
    },
  );

  it.each(invalidDetachedPayloads)(
    'should throw when the provided option "detachedPayload" is invalid.',
    async (detachedPayload) => {
      await expect(
        deserialize(unencodedProtectedAttachedTokenWithoutDot, { detachedPayload }),
      ).rejects.toThrowWithMessage(TypeError, 'The provided option "detachedPayload" is invalid.');
    },
  );

  it.each(invalidTokens)(
    'should throw when the provided Flattened JSON Web Signature Token is invalid.',
    async (token) => {
      await expect(deserialize(token)).rejects.toThrowWithMessage(
        TypeError,
        'The provided Flattened JSON Web Signature Token is invalid.',
      );
    },
  );

  it('should throw when deserializing a Detached Flattened JSON Web Signature Token and not providing a Detached Payload.', async () => {
    await expect(deserialize(unencodedProtectedDetachedTokenWithoutDot)).rejects.toThrowWithMessage(
      InvalidJsonWebSignatureError,
      'The JSON Web Signature requires a valid Payload.',
    );
  });

  it('should throw when providing a Detached Payload for a Flattened JSON Web Signature Token that already has a Payload.', async () => {
    await expect(
      deserialize(unencodedProtectedAttachedTokenWithoutDot, { detachedPayload: payloadWithoutDot }),
    ).rejects.toThrowWithMessage(
      InvalidJsonWebSignatureError,
      'The provided JSON Web Signature already has a defined Payload.',
    );
  });

  it('should throw when the JSON Web Signature Digital Signature Algorithm of the Flattened JSON Web Signature Token is unexpected.', async () => {
    await expect(
      deserialize(unencodedProtectedAttachedTokenWithoutDot, { expectedDigitalSignatureAlgorithms: ['HS512'] }),
    ).rejects.toThrowWithMessage(
      InvalidJsonWebSignatureError,
      'Unexpected JSON Web Signature Digital Signature Algorithm "HS256".',
    );
  });

  it('should throw when the provided Signature fails to deserialize the provided Flattened JSON Web Signature Token.', async () => {
    await expect(deserialize(wrongSignatureToken, { jsonWebKey })).rejects.toThrow();
  });

  it('should return the deserialized Flattened JSON Web Signature from a Protected Attached Unencoded Token without a dot.', async () => {
    let jsonWebSignature!: FlattenedJsonWebSignature;

    await expect(async () => {
      jsonWebSignature = await deserialize(unencodedProtectedAttachedTokenWithoutDot, { jsonWebKey });
    }).resolves.not.toThrow();

    expect(jsonWebSignature.header).toBeInstanceOf(JsonWebSignatureHeader);
    expect(jsonWebSignature.header.parameters).toStrictEqual(unencodedProtectedHeader);

    expect(jsonWebSignature.protectedHeader).toStrictEqual(unencodedProtectedHeader);
    expect(jsonWebSignature.unprotectedHeader).toBeUndefined();

    expect(jsonWebSignature.payload).toStrictEqual(payloadWithoutDot);
  });

  it('should throw when deserializing a Flattened JSON Web Signature from a Protected Attached Unencoded Token without a dot that is missing the JOSE Header Parameter "b64".', async () => {
    await expect(
      deserialize(missingUnencodedProtectedAttachedTokenWithoutDot, { jsonWebKey }),
    ).rejects.toThrowWithMessage(InvalidJsonWebSignatureError, 'The provided JSON Web Signature is invalid.');
  });

  it('should throw when deserializing a Flattened JSON Web Signature from an Unprotected Attached Unencoded Token without a dot.', async () => {
    await expect(
      deserialize(badUnencodedUnprotectedAttachedTokenWithoutDot, { jsonWebKey }),
    ).rejects.toThrowWithMessage(InvalidJsonWebSignatureError, 'The provided JSON Web Signature is invalid.');
  });

  it('should throw when deserializing a Flattened JSON Web Signature from an Unprotected Attached Unencoded Token without a dot that is missing the JOSE Header Parameter "b64".', async () => {
    await expect(
      deserialize(missingUnencodedUnprotectedAttachedTokenWithoutDot, { jsonWebKey }),
    ).rejects.toThrowWithMessage(InvalidJsonWebSignatureError, 'The provided JSON Web Signature is invalid.');
  });

  it('should return the deserialized Flattened JSON Web Signature from a Protected and Unprotected Attached Unencoded Token without a dot.', async () => {
    let jsonWebSignature!: FlattenedJsonWebSignature;

    await expect(async () => {
      jsonWebSignature = await deserialize(unencodedFullAttachedTokenWithoutDot, { jsonWebKey });
    }).resolves.not.toThrow();

    expect(jsonWebSignature.header).toBeInstanceOf(JsonWebSignatureHeader);
    expect(jsonWebSignature.header.parameters).toStrictEqual<Partial<JsonWebSignatureHeaderParameters>>({
      ...unencodedProtectedHeader,
      ...unprotectedHeader,
    });

    expect(jsonWebSignature.protectedHeader).toStrictEqual(unencodedProtectedHeader);
    expect(jsonWebSignature.unprotectedHeader).toStrictEqual(unprotectedHeader);

    expect(jsonWebSignature.payload).toStrictEqual(payloadWithoutDot);
  });

  it('should throw when deserializing a Flattened JSON Web Signature from a Protected and Unprotected Attached Unencoded Token without a dot.', async () => {
    await expect(deserialize(badUnencodedFullAttachedTokenWithoutDot, { jsonWebKey })).rejects.toThrowWithMessage(
      InvalidJsonWebSignatureError,
      'The provided JSON Web Signature is invalid.',
    );
  });

  it('should throw when deserializing a Flattened JSON Web Signature from a Protected and Unprotected Attached Unencoded Token without a dot that is missing the JOSE Header Parameter "b64".', async () => {
    await expect(deserialize(missingUnencodedFullAttachedTokenWithoutDot, { jsonWebKey })).rejects.toThrowWithMessage(
      InvalidJsonWebSignatureError,
      'The provided JSON Web Signature is invalid.',
    );
  });

  it('should return the deserialized Flattened JSON Web Signature from a Protected Detached Unencoded Token without a dot.', async () => {
    let jsonWebSignature!: FlattenedJsonWebSignature;

    await expect(async () => {
      jsonWebSignature = await deserialize(unencodedProtectedDetachedTokenWithoutDot, {
        jsonWebKey,
        detachedPayload: payloadWithoutDot,
      });
    }).resolves.not.toThrow();

    expect(jsonWebSignature.header).toBeInstanceOf(JsonWebSignatureHeader);
    expect(jsonWebSignature.header.parameters).toStrictEqual(unencodedProtectedHeader);

    expect(jsonWebSignature.protectedHeader).toStrictEqual(unencodedProtectedHeader);
    expect(jsonWebSignature.unprotectedHeader).toBeUndefined();

    expect(jsonWebSignature.payload).toStrictEqual(payloadWithoutDot);
  });

  it('should throw when deserializing a Flattened JSON Web Signature from a Protected Detached Unencoded Token without a dot that is missing the JOSE Header Parameter "b64".', async () => {
    await expect(
      deserialize(missingUnencodedProtectedDetachedTokenWithoutDot, {
        jsonWebKey,
        detachedPayload: payloadWithoutDot,
      }),
    ).rejects.toThrowWithMessage(InvalidJsonWebSignatureError, 'The provided JSON Web Signature is invalid.');
  });

  it('should throw when deserializing a Flattened JSON Web Signature from an Unprotected Detached Unencoded Token without a dot.', async () => {
    await expect(
      deserialize(badUnencodedUnprotectedDetachedTokenWithoutDot, {
        jsonWebKey,
        detachedPayload: payloadWithoutDot,
      }),
    ).rejects.toThrowWithMessage(InvalidJsonWebSignatureError, 'The provided JSON Web Signature is invalid.');
  });

  it('should throw when deserializing a Flattened JSON Web Signature from an Unprotected Detached Unencoded Token without a dot that is missing the JOSE Header Parameter "b64".', async () => {
    await expect(
      deserialize(missingUnencodedUnprotectedDetachedTokenWithoutDot, {
        jsonWebKey,
        detachedPayload: payloadWithoutDot,
      }),
    ).rejects.toThrowWithMessage(InvalidJsonWebSignatureError, 'The provided JSON Web Signature is invalid.');
  });

  it('should return the deserialized Flattened JSON Web Signature from a Protected and Unprotected Detached Unencoded Token without a dot.', async () => {
    let jsonWebSignature!: FlattenedJsonWebSignature;

    await expect(async () => {
      jsonWebSignature = await deserialize(unencodedFullDetachedTokenWithoutDot, {
        jsonWebKey,
        detachedPayload: payloadWithoutDot,
      });
    }).resolves.not.toThrow();

    expect(jsonWebSignature.header).toBeInstanceOf(JsonWebSignatureHeader);
    expect(jsonWebSignature.header.parameters).toStrictEqual<Partial<JsonWebSignatureHeaderParameters>>({
      ...unencodedProtectedHeader,
      ...unprotectedHeader,
    });

    expect(jsonWebSignature.protectedHeader).toStrictEqual(unencodedProtectedHeader);
    expect(jsonWebSignature.unprotectedHeader).toStrictEqual(unprotectedHeader);

    expect(jsonWebSignature.payload).toStrictEqual(payloadWithoutDot);
  });

  it('should throw when deserializing a Flattened JSON Web Signature from a Protected and Unprotected Detached Unencoded Token without a dot.', async () => {
    await expect(
      deserialize(badUnencodedFullDetachedTokenWithoutDot, {
        jsonWebKey,
        detachedPayload: payloadWithoutDot,
      }),
    ).rejects.toThrowWithMessage(InvalidJsonWebSignatureError, 'The provided JSON Web Signature is invalid.');
  });

  it('should throw when deserializing a Flattened JSON Web Signature from a Protected and Unprotected Detached Unencoded Token without a dot that is missing the JOSE Header Parameter "b64".', async () => {
    await expect(
      deserialize(missingUnencodedFullDetachedTokenWithoutDot, {
        jsonWebKey,
        detachedPayload: payloadWithoutDot,
      }),
    ).rejects.toThrowWithMessage(InvalidJsonWebSignatureError, 'The provided JSON Web Signature is invalid.');
  });

  it('should return the deserialized Flattened JSON Web Signature from a Protected Detached Unencoded Token with a dot.', async () => {
    let jsonWebSignature!: FlattenedJsonWebSignature;

    await expect(async () => {
      jsonWebSignature = await deserialize(unencodedProtectedDetachedTokenWithDot, {
        jsonWebKey,
        detachedPayload: payloadWithDot,
      });
    }).resolves.not.toThrow();

    expect(jsonWebSignature.header).toBeInstanceOf(JsonWebSignatureHeader);
    expect(jsonWebSignature.header.parameters).toStrictEqual(unencodedProtectedHeader);

    expect(jsonWebSignature.protectedHeader).toStrictEqual(unencodedProtectedHeader);
    expect(jsonWebSignature.unprotectedHeader).toBeUndefined();

    expect(jsonWebSignature.payload).toStrictEqual(payloadWithDot);
  });

  it('should throw when deserializing a Flattened JSON Web Signature from a Protected Detached Unencoded Token with a dot that is missing the JOSE Header Parameter "b64".', async () => {
    await expect(
      deserialize(missingUnencodedProtectedDetachedTokenWithDot, {
        jsonWebKey,
        detachedPayload: payloadWithDot,
      }),
    ).rejects.toThrowWithMessage(InvalidJsonWebSignatureError, 'The provided JSON Web Signature is invalid.');
  });

  it('should throw when deserializing a Flattened JSON Web Signature from an Unprotected Detached Unencoded Token with a dot.', async () => {
    await expect(
      deserialize(badUnencodedUnprotectedDetachedTokenWithDot, {
        jsonWebKey,
        detachedPayload: payloadWithDot,
      }),
    ).rejects.toThrowWithMessage(InvalidJsonWebSignatureError, 'The provided JSON Web Signature is invalid.');
  });

  it('should throw when deserializing a Flattened JSON Web Signature from an Unprotected Detached Unencoded Token with a dot that is missing the JOSE Header Parameter "b64".', async () => {
    await expect(
      deserialize(missingUnencodedUnprotectedDetachedTokenWithDot, {
        jsonWebKey,
        detachedPayload: payloadWithDot,
      }),
    ).rejects.toThrowWithMessage(InvalidJsonWebSignatureError, 'The provided JSON Web Signature is invalid.');
  });

  it('should return the deserialized Flattened JSON Web Signature from a Protected and Unprotected Detached Unencoded Token with a dot.', async () => {
    let jsonWebSignature!: FlattenedJsonWebSignature;

    await expect(async () => {
      jsonWebSignature = await deserialize(unencodedFullDetachedTokenWithDot, {
        jsonWebKey,
        detachedPayload: payloadWithDot,
      });
    }).resolves.not.toThrow();

    expect(jsonWebSignature.header).toBeInstanceOf(JsonWebSignatureHeader);
    expect(jsonWebSignature.header.parameters).toStrictEqual<Partial<JsonWebSignatureHeaderParameters>>({
      ...unencodedProtectedHeader,
      ...unprotectedHeader,
    });

    expect(jsonWebSignature.protectedHeader).toStrictEqual(unencodedProtectedHeader);
    expect(jsonWebSignature.unprotectedHeader).toStrictEqual(unprotectedHeader);

    expect(jsonWebSignature.payload).toStrictEqual(payloadWithDot);
  });

  it('should throw when deserializing a Flattened JSON Web Signature from a Protected and Unprotected Detached Unencoded Token with a dot.', async () => {
    await expect(
      deserialize(badUnencodedFullDetachedTokenWithDot, { jsonWebKey, detachedPayload: payloadWithDot }),
    ).rejects.toThrowWithMessage(InvalidJsonWebSignatureError, 'The provided JSON Web Signature is invalid.');
  });

  it('should throw when deserializing a Flattened JSON Web Signature from a Protected and Unprotected Detached Unencoded Token with a dot that is missing the JOSE Header Parameter "b64".', async () => {
    await expect(
      deserialize(missingUnencodedFullDetachedTokenWithDot, {
        jsonWebKey,
        detachedPayload: payloadWithDot,
      }),
    ).rejects.toThrowWithMessage(InvalidJsonWebSignatureError, 'The provided JSON Web Signature is invalid.');
  });

  it('should return the deserialized Flattened JSON Web Signature from a Protected Attached Encoded Token without a dot.', async () => {
    let jsonWebSignature!: FlattenedJsonWebSignature;

    await expect(async () => {
      jsonWebSignature = await deserialize(encodedProtectedAttachedToken, { jsonWebKey });
    }).resolves.not.toThrow();

    expect(jsonWebSignature.header).toBeInstanceOf(JsonWebSignatureHeader);
    expect(jsonWebSignature.header.parameters).toStrictEqual(encodedProtectedHeader);

    expect(jsonWebSignature.protectedHeader).toStrictEqual(encodedProtectedHeader);
    expect(jsonWebSignature.unprotectedHeader).toBeUndefined();

    expect(jsonWebSignature.payload).toStrictEqual(payloadWithoutDot);
  });

  it('should return the deserialized Flattened JSON Web Signature from an Unprotected Attached Encoded Token without a dot.', async () => {
    let jsonWebSignature!: FlattenedJsonWebSignature;

    await expect(async () => {
      jsonWebSignature = await deserialize(encodedUnprotectedAttachedToken, { jsonWebKey });
    }).resolves.not.toThrow();

    expect(jsonWebSignature.header).toBeInstanceOf(JsonWebSignatureHeader);
    expect(jsonWebSignature.header.parameters).toStrictEqual<Partial<JsonWebSignatureHeaderParameters>>({
      ...encodedProtectedHeader,
      ...unprotectedHeader,
    });

    expect(jsonWebSignature.protectedHeader).toBeUndefined();
    expect(jsonWebSignature.unprotectedHeader).toStrictEqual<Partial<JsonWebSignatureHeaderParameters>>({
      ...encodedProtectedHeader,
      ...unprotectedHeader,
    });

    expect(jsonWebSignature.payload).toStrictEqual(payloadWithoutDot);
  });

  it('should return the deserialized Flattened JSON Web Signature from a Protected and Unprotected Attached Encoded Token without a dot.', async () => {
    let jsonWebSignature!: FlattenedJsonWebSignature;

    await expect(async () => {
      jsonWebSignature = await deserialize(encodedFullAttachedToken, { jsonWebKey });
    }).resolves.not.toThrow();

    expect(jsonWebSignature.header).toBeInstanceOf(JsonWebSignatureHeader);
    expect(jsonWebSignature.header.parameters).toStrictEqual<Partial<JsonWebSignatureHeaderParameters>>({
      ...encodedProtectedHeader,
      ...unprotectedHeader,
    });

    expect(jsonWebSignature.protectedHeader).toStrictEqual(encodedProtectedHeader);
    expect(jsonWebSignature.unprotectedHeader).toStrictEqual(unprotectedHeader);

    expect(jsonWebSignature.payload).toStrictEqual(payloadWithoutDot);
  });

  it('should return the deserialized Flattened JSON Web Signature from a Protected Detached Encoded Token without a dot.', async () => {
    let jsonWebSignature!: FlattenedJsonWebSignature;

    await expect(async () => {
      jsonWebSignature = await deserialize(encodedProtectedDetachedToken, {
        jsonWebKey,
        detachedPayload: payloadWithoutDot,
      });
    }).resolves.not.toThrow();

    expect(jsonWebSignature.header).toBeInstanceOf(JsonWebSignatureHeader);
    expect(jsonWebSignature.header.parameters).toStrictEqual(encodedProtectedHeader);

    expect(jsonWebSignature.protectedHeader).toStrictEqual(encodedProtectedHeader);
    expect(jsonWebSignature.unprotectedHeader).toBeUndefined();

    expect(jsonWebSignature.payload).toStrictEqual(payloadWithoutDot);
  });

  it('should return the deserialized Flattened JSON Web Signature from an Unprotected Detached Encoded Token without a dot.', async () => {
    let jsonWebSignature!: FlattenedJsonWebSignature;

    await expect(async () => {
      jsonWebSignature = await deserialize(encodedUnprotectedDetachedToken, {
        jsonWebKey,
        detachedPayload: payloadWithoutDot,
      });
    }).resolves.not.toThrow();

    expect(jsonWebSignature.header).toBeInstanceOf(JsonWebSignatureHeader);
    expect(jsonWebSignature.header.parameters).toStrictEqual<Partial<JsonWebSignatureHeaderParameters>>({
      ...encodedProtectedHeader,
      ...unprotectedHeader,
    });

    expect(jsonWebSignature.protectedHeader).toBeUndefined();
    expect(jsonWebSignature.unprotectedHeader).toStrictEqual<Partial<JsonWebSignatureHeaderParameters>>({
      ...encodedProtectedHeader,
      ...unprotectedHeader,
    });

    expect(jsonWebSignature.payload).toStrictEqual(payloadWithoutDot);
  });

  it('should return the deserialized Flattened JSON Web Signature from a Protected and Unprotected Detached Encoded Token without a dot.', async () => {
    let jsonWebSignature!: FlattenedJsonWebSignature;

    await expect(async () => {
      jsonWebSignature = await deserialize(encodedFullDetachedToken, {
        jsonWebKey,
        detachedPayload: payloadWithoutDot,
      });
    }).resolves.not.toThrow();

    expect(jsonWebSignature.header).toBeInstanceOf(JsonWebSignatureHeader);
    expect(jsonWebSignature.header.parameters).toStrictEqual<Partial<JsonWebSignatureHeaderParameters>>({
      ...encodedProtectedHeader,
      ...unprotectedHeader,
    });

    expect(jsonWebSignature.protectedHeader).toStrictEqual(encodedProtectedHeader);
    expect(jsonWebSignature.unprotectedHeader).toStrictEqual(unprotectedHeader);

    expect(jsonWebSignature.payload).toStrictEqual(payloadWithoutDot);
  });
});
