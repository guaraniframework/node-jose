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

const invalidJwks: any[] = [undefined, true, 1, 1.2, 1n, 'a', Symbol('a'), Buffer, Buffer.alloc(1), () => 1, {}, []];

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

  const jwk = new OctetSequenceJsonWebKey({ kty: 'oct', k: 'qDM80igvja4Tg_tNsEuWDhl2bMM6_NgJEldFhIEuwqQ' });

  it.each(invalidDeserializeOptions)('should throw when the provided options is invalid.', async (options) => {
    await expect(deserialize(unencodedProtectedAttachedTokenWithoutDot, options)).rejects.toThrowWithMessage(
      TypeError,
      'The provided options is invalid.',
    );
  });

  it.each(invalidJwks)('should throw when the provided option "jwk" is invalid.', async (jwk) => {
    await expect(deserialize(unencodedProtectedAttachedTokenWithoutDot, { jwk })).rejects.toThrowWithMessage(
      TypeError,
      'The provided option "jwk" is invalid.',
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
    await expect(deserialize(wrongSignatureToken, { jwk })).rejects.toThrow();
  });

  it('should return the deserialized Flattened JSON Web Signature from a Protected Attached Unencoded Token without a dot.', async () => {
    let jws!: FlattenedJsonWebSignature;

    await expect(async () => {
      jws = await deserialize(unencodedProtectedAttachedTokenWithoutDot, { jwk });
    }).resolves.not.toThrow();

    expect(jws.header).toBeInstanceOf(JsonWebSignatureHeader);
    expect(jws.header.parameters).toStrictEqual(unencodedProtectedHeader);

    expect(jws.protectedHeader).toStrictEqual(unencodedProtectedHeader);
    expect(jws.unprotectedHeader).toBeUndefined();

    expect(jws.payload).toStrictEqual(payloadWithoutDot);
  });

  it('should throw when deserializing a Flattened JSON Web Signature from a Protected Attached Unencoded Token without a dot that is missing the JOSE Header Parameter "b64".', async () => {
    await expect(deserialize(missingUnencodedProtectedAttachedTokenWithoutDot, { jwk })).rejects.toThrowWithMessage(
      InvalidJsonWebSignatureError,
      'The provided JSON Web Signature is invalid.',
    );
  });

  it('should throw when deserializing a Flattened JSON Web Signature from an Unprotected Attached Unencoded Token without a dot.', async () => {
    await expect(deserialize(badUnencodedUnprotectedAttachedTokenWithoutDot, { jwk })).rejects.toThrowWithMessage(
      InvalidJsonWebSignatureError,
      'The provided JSON Web Signature is invalid.',
    );
  });

  it('should throw when deserializing a Flattened JSON Web Signature from an Unprotected Attached Unencoded Token without a dot that is missing the JOSE Header Parameter "b64".', async () => {
    await expect(deserialize(missingUnencodedUnprotectedAttachedTokenWithoutDot, { jwk })).rejects.toThrowWithMessage(
      InvalidJsonWebSignatureError,
      'The provided JSON Web Signature is invalid.',
    );
  });

  it('should return the deserialized Flattened JSON Web Signature from a Protected and Unprotected Attached Unencoded Token without a dot.', async () => {
    let jws!: FlattenedJsonWebSignature;

    await expect(async () => {
      jws = await deserialize(unencodedFullAttachedTokenWithoutDot, { jwk });
    }).resolves.not.toThrow();

    expect(jws.header).toBeInstanceOf(JsonWebSignatureHeader);
    expect(jws.header.parameters).toStrictEqual<Partial<JsonWebSignatureHeaderParameters>>({
      ...unencodedProtectedHeader,
      ...unprotectedHeader,
    });

    expect(jws.protectedHeader).toStrictEqual(unencodedProtectedHeader);
    expect(jws.unprotectedHeader).toStrictEqual(unprotectedHeader);

    expect(jws.payload).toStrictEqual(payloadWithoutDot);
  });

  it('should throw when deserializing a Flattened JSON Web Signature from a Protected and Unprotected Attached Unencoded Token without a dot.', async () => {
    await expect(deserialize(badUnencodedFullAttachedTokenWithoutDot, { jwk })).rejects.toThrowWithMessage(
      InvalidJsonWebSignatureError,
      'The provided JSON Web Signature is invalid.',
    );
  });

  it('should throw when deserializing a Flattened JSON Web Signature from a Protected and Unprotected Attached Unencoded Token without a dot that is missing the JOSE Header Parameter "b64".', async () => {
    await expect(deserialize(missingUnencodedFullAttachedTokenWithoutDot, { jwk })).rejects.toThrowWithMessage(
      InvalidJsonWebSignatureError,
      'The provided JSON Web Signature is invalid.',
    );
  });

  it('should return the deserialized Flattened JSON Web Signature from a Protected Detached Unencoded Token without a dot.', async () => {
    let jws!: FlattenedJsonWebSignature;

    await expect(async () => {
      jws = await deserialize(unencodedProtectedDetachedTokenWithoutDot, { jwk, detachedPayload: payloadWithoutDot });
    }).resolves.not.toThrow();

    expect(jws.header).toBeInstanceOf(JsonWebSignatureHeader);
    expect(jws.header.parameters).toStrictEqual(unencodedProtectedHeader);

    expect(jws.protectedHeader).toStrictEqual(unencodedProtectedHeader);
    expect(jws.unprotectedHeader).toBeUndefined();

    expect(jws.payload).toStrictEqual(payloadWithoutDot);
  });

  it('should throw when deserializing a Flattened JSON Web Signature from a Protected Detached Unencoded Token without a dot that is missing the JOSE Header Parameter "b64".', async () => {
    await expect(
      deserialize(missingUnencodedProtectedDetachedTokenWithoutDot, { jwk, detachedPayload: payloadWithoutDot }),
    ).rejects.toThrowWithMessage(InvalidJsonWebSignatureError, 'The provided JSON Web Signature is invalid.');
  });

  it('should throw when deserializing a Flattened JSON Web Signature from an Unprotected Detached Unencoded Token without a dot.', async () => {
    await expect(
      deserialize(badUnencodedUnprotectedDetachedTokenWithoutDot, { jwk, detachedPayload: payloadWithoutDot }),
    ).rejects.toThrowWithMessage(InvalidJsonWebSignatureError, 'The provided JSON Web Signature is invalid.');
  });

  it('should throw when deserializing a Flattened JSON Web Signature from an Unprotected Detached Unencoded Token without a dot that is missing the JOSE Header Parameter "b64".', async () => {
    await expect(
      deserialize(missingUnencodedUnprotectedDetachedTokenWithoutDot, { jwk, detachedPayload: payloadWithoutDot }),
    ).rejects.toThrowWithMessage(InvalidJsonWebSignatureError, 'The provided JSON Web Signature is invalid.');
  });

  it('should return the deserialized Flattened JSON Web Signature from a Protected and Unprotected Detached Unencoded Token without a dot.', async () => {
    let jws!: FlattenedJsonWebSignature;

    await expect(async () => {
      jws = await deserialize(unencodedFullDetachedTokenWithoutDot, { jwk, detachedPayload: payloadWithoutDot });
    }).resolves.not.toThrow();

    expect(jws.header).toBeInstanceOf(JsonWebSignatureHeader);
    expect(jws.header.parameters).toStrictEqual<Partial<JsonWebSignatureHeaderParameters>>({
      ...unencodedProtectedHeader,
      ...unprotectedHeader,
    });

    expect(jws.protectedHeader).toStrictEqual(unencodedProtectedHeader);
    expect(jws.unprotectedHeader).toStrictEqual(unprotectedHeader);

    expect(jws.payload).toStrictEqual(payloadWithoutDot);
  });

  it('should throw when deserializing a Flattened JSON Web Signature from a Protected and Unprotected Detached Unencoded Token without a dot.', async () => {
    await expect(
      deserialize(badUnencodedFullDetachedTokenWithoutDot, { jwk, detachedPayload: payloadWithoutDot }),
    ).rejects.toThrowWithMessage(InvalidJsonWebSignatureError, 'The provided JSON Web Signature is invalid.');
  });

  it('should throw when deserializing a Flattened JSON Web Signature from a Protected and Unprotected Detached Unencoded Token without a dot that is missing the JOSE Header Parameter "b64".', async () => {
    await expect(
      deserialize(missingUnencodedFullDetachedTokenWithoutDot, { jwk, detachedPayload: payloadWithoutDot }),
    ).rejects.toThrowWithMessage(InvalidJsonWebSignatureError, 'The provided JSON Web Signature is invalid.');
  });

  it('should return the deserialized Flattened JSON Web Signature from a Protected Detached Unencoded Token with a dot.', async () => {
    let jws!: FlattenedJsonWebSignature;

    await expect(async () => {
      jws = await deserialize(unencodedProtectedDetachedTokenWithDot, { jwk, detachedPayload: payloadWithDot });
    }).resolves.not.toThrow();

    expect(jws.header).toBeInstanceOf(JsonWebSignatureHeader);
    expect(jws.header.parameters).toStrictEqual(unencodedProtectedHeader);

    expect(jws.protectedHeader).toStrictEqual(unencodedProtectedHeader);
    expect(jws.unprotectedHeader).toBeUndefined();

    expect(jws.payload).toStrictEqual(payloadWithDot);
  });

  it('should throw when deserializing a Flattened JSON Web Signature from a Protected Detached Unencoded Token with a dot that is missing the JOSE Header Parameter "b64".', async () => {
    await expect(
      deserialize(missingUnencodedProtectedDetachedTokenWithDot, { jwk, detachedPayload: payloadWithDot }),
    ).rejects.toThrowWithMessage(InvalidJsonWebSignatureError, 'The provided JSON Web Signature is invalid.');
  });

  it('should throw when deserializing a Flattened JSON Web Signature from an Unprotected Detached Unencoded Token with a dot.', async () => {
    await expect(
      deserialize(badUnencodedUnprotectedDetachedTokenWithDot, { jwk, detachedPayload: payloadWithDot }),
    ).rejects.toThrowWithMessage(InvalidJsonWebSignatureError, 'The provided JSON Web Signature is invalid.');
  });

  it('should throw when deserializing a Flattened JSON Web Signature from an Unprotected Detached Unencoded Token with a dot that is missing the JOSE Header Parameter "b64".', async () => {
    await expect(
      deserialize(missingUnencodedUnprotectedDetachedTokenWithDot, { jwk, detachedPayload: payloadWithDot }),
    ).rejects.toThrowWithMessage(InvalidJsonWebSignatureError, 'The provided JSON Web Signature is invalid.');
  });

  it('should return the deserialized Flattened JSON Web Signature from a Protected and Unprotected Detached Unencoded Token with a dot.', async () => {
    let jws!: FlattenedJsonWebSignature;

    await expect(async () => {
      jws = await deserialize(unencodedFullDetachedTokenWithDot, { jwk, detachedPayload: payloadWithDot });
    }).resolves.not.toThrow();

    expect(jws.header).toBeInstanceOf(JsonWebSignatureHeader);
    expect(jws.header.parameters).toStrictEqual<Partial<JsonWebSignatureHeaderParameters>>({
      ...unencodedProtectedHeader,
      ...unprotectedHeader,
    });

    expect(jws.protectedHeader).toStrictEqual(unencodedProtectedHeader);
    expect(jws.unprotectedHeader).toStrictEqual(unprotectedHeader);

    expect(jws.payload).toStrictEqual(payloadWithDot);
  });

  it('should throw when deserializing a Flattened JSON Web Signature from a Protected and Unprotected Detached Unencoded Token with a dot.', async () => {
    await expect(
      deserialize(badUnencodedFullDetachedTokenWithDot, { jwk, detachedPayload: payloadWithDot }),
    ).rejects.toThrowWithMessage(InvalidJsonWebSignatureError, 'The provided JSON Web Signature is invalid.');
  });

  it('should throw when deserializing a Flattened JSON Web Signature from a Protected and Unprotected Detached Unencoded Token with a dot that is missing the JOSE Header Parameter "b64".', async () => {
    await expect(
      deserialize(missingUnencodedFullDetachedTokenWithDot, { jwk, detachedPayload: payloadWithDot }),
    ).rejects.toThrowWithMessage(InvalidJsonWebSignatureError, 'The provided JSON Web Signature is invalid.');
  });

  it('should return the deserialized Flattened JSON Web Signature from a Protected Attached Encoded Token without a dot.', async () => {
    let jws!: FlattenedJsonWebSignature;

    await expect(async () => {
      jws = await deserialize(encodedProtectedAttachedToken, { jwk });
    }).resolves.not.toThrow();

    expect(jws.header).toBeInstanceOf(JsonWebSignatureHeader);
    expect(jws.header.parameters).toStrictEqual(encodedProtectedHeader);

    expect(jws.protectedHeader).toStrictEqual(encodedProtectedHeader);
    expect(jws.unprotectedHeader).toBeUndefined();

    expect(jws.payload).toStrictEqual(payloadWithoutDot);
  });

  it('should return the deserialized Flattened JSON Web Signature from an Unprotected Attached Encoded Token without a dot.', async () => {
    let jws!: FlattenedJsonWebSignature;

    await expect(async () => {
      jws = await deserialize(encodedUnprotectedAttachedToken, { jwk });
    }).resolves.not.toThrow();

    expect(jws.header).toBeInstanceOf(JsonWebSignatureHeader);
    expect(jws.header.parameters).toStrictEqual<Partial<JsonWebSignatureHeaderParameters>>({
      ...encodedProtectedHeader,
      ...unprotectedHeader,
    });

    expect(jws.protectedHeader).toBeUndefined();
    expect(jws.unprotectedHeader).toStrictEqual<Partial<JsonWebSignatureHeaderParameters>>({
      ...encodedProtectedHeader,
      ...unprotectedHeader,
    });

    expect(jws.payload).toStrictEqual(payloadWithoutDot);
  });

  it('should return the deserialized Flattened JSON Web Signature from a Protected and Unprotected Attached Encoded Token without a dot.', async () => {
    let jws!: FlattenedJsonWebSignature;

    await expect(async () => {
      jws = await deserialize(encodedFullAttachedToken, { jwk });
    }).resolves.not.toThrow();

    expect(jws.header).toBeInstanceOf(JsonWebSignatureHeader);
    expect(jws.header.parameters).toStrictEqual<Partial<JsonWebSignatureHeaderParameters>>({
      ...encodedProtectedHeader,
      ...unprotectedHeader,
    });

    expect(jws.protectedHeader).toStrictEqual(encodedProtectedHeader);
    expect(jws.unprotectedHeader).toStrictEqual(unprotectedHeader);

    expect(jws.payload).toStrictEqual(payloadWithoutDot);
  });

  it('should return the deserialized Flattened JSON Web Signature from a Protected Detached Encoded Token without a dot.', async () => {
    let jws!: FlattenedJsonWebSignature;

    await expect(async () => {
      jws = await deserialize(encodedProtectedDetachedToken, { jwk, detachedPayload: payloadWithoutDot });
    }).resolves.not.toThrow();

    expect(jws.header).toBeInstanceOf(JsonWebSignatureHeader);
    expect(jws.header.parameters).toStrictEqual(encodedProtectedHeader);

    expect(jws.protectedHeader).toStrictEqual(encodedProtectedHeader);
    expect(jws.unprotectedHeader).toBeUndefined();

    expect(jws.payload).toStrictEqual(payloadWithoutDot);
  });

  it('should return the deserialized Flattened JSON Web Signature from an Unprotected Detached Encoded Token without a dot.', async () => {
    let jws!: FlattenedJsonWebSignature;

    await expect(async () => {
      jws = await deserialize(encodedUnprotectedDetachedToken, { jwk, detachedPayload: payloadWithoutDot });
    }).resolves.not.toThrow();

    expect(jws.header).toBeInstanceOf(JsonWebSignatureHeader);
    expect(jws.header.parameters).toStrictEqual<Partial<JsonWebSignatureHeaderParameters>>({
      ...encodedProtectedHeader,
      ...unprotectedHeader,
    });

    expect(jws.protectedHeader).toBeUndefined();
    expect(jws.unprotectedHeader).toStrictEqual<Partial<JsonWebSignatureHeaderParameters>>({
      ...encodedProtectedHeader,
      ...unprotectedHeader,
    });

    expect(jws.payload).toStrictEqual(payloadWithoutDot);
  });

  it('should return the deserialized Flattened JSON Web Signature from a Protected and Unprotected Detached Encoded Token without a dot.', async () => {
    let jws!: FlattenedJsonWebSignature;

    await expect(async () => {
      jws = await deserialize(encodedFullDetachedToken, { jwk, detachedPayload: payloadWithoutDot });
    }).resolves.not.toThrow();

    expect(jws.header).toBeInstanceOf(JsonWebSignatureHeader);
    expect(jws.header.parameters).toStrictEqual<Partial<JsonWebSignatureHeaderParameters>>({
      ...encodedProtectedHeader,
      ...unprotectedHeader,
    });

    expect(jws.protectedHeader).toStrictEqual(encodedProtectedHeader);
    expect(jws.unprotectedHeader).toStrictEqual(unprotectedHeader);

    expect(jws.payload).toStrictEqual(payloadWithoutDot);
  });
});
