import { Buffer } from 'buffer';

import { InvalidJsonWebSignatureError } from '../../../errors/invalid-jsonwebsignature.error';
import { JsonWebSignatureHeader } from '../../jsonwebsignature-header';
import { JsonWebSignatureHeaderParameters } from '../../jsonwebsignature-header.parameters';
import { decode } from './decode';
import { GeneralJsonWebSignatureParameters } from './general-jsonwebsignature.parameters';
import { GeneralJsonWebSignatureToken } from './general-jsonwebsignature.token';

const invalidTokens: any[] = [undefined, null, true, 1, 1.2, 1n, Symbol('a'), Buffer, Buffer.alloc(1), () => 1, []];

const invalidTokenFormats: any[] = [
  {},
  { payload: undefined },
  { payload: null },
  { payload: true },
  { payload: 1 },
  { payload: 1.2 },
  { payload: 1n },
  { payload: Symbol('a') },
  { payload: Buffer },
  { payload: Buffer.alloc(1) },
  { payload: () => 1 },
  { payload: {} },
  { payload: [] },
  { payload: '' },
  { signatures: undefined },
  { signatures: null },
  { signatures: true },
  { signatures: 1 },
  { signatures: 1.2 },
  { signatures: 1n },
  { signatures: 'a' },
  { signatures: Symbol('a') },
  { signatures: Buffer },
  { signatures: Buffer.alloc(1) },
  { signatures: () => 1 },
  { signatures: {} },
  { signatures: [] },
  { signatures: [undefined] },
  { signatures: [null] },
  { signatures: [true] },
  { signatures: [1] },
  { signatures: [1.2] },
  { signatures: [1n] },
  { signatures: ['a'] },
  { signatures: [Symbol('a')] },
  { signatures: [Buffer] },
  { signatures: [Buffer.alloc(1)] },
  { signatures: [() => 1] },
  { signatures: [[]] },
  { signatures: [{}] },
  { signatures: [{ protected: undefined }] },
  { signatures: [{ protected: null }] },
  { signatures: [{ protected: true }] },
  { signatures: [{ protected: 1 }] },
  { signatures: [{ protected: 1.2 }] },
  { signatures: [{ protected: 1n }] },
  { signatures: [{ protected: Symbol('a') }] },
  { signatures: [{ protected: Buffer }] },
  { signatures: [{ protected: Buffer.alloc(1) }] },
  { signatures: [{ protected: () => 1 }] },
  { signatures: [{ protected: {} }] },
  { signatures: [{ protected: [] }] },
  { signatures: [{ protected: '' }] },
  { signatures: [{ protected: 'eyJhbGciOiJIUzI1NiJ9', header: undefined }] },
  { signatures: [{ protected: 'eyJhbGciOiJIUzI1NiJ9', header: null }] },
  { signatures: [{ protected: 'eyJhbGciOiJIUzI1NiJ9', header: true }] },
  { signatures: [{ protected: 'eyJhbGciOiJIUzI1NiJ9', header: 1 }] },
  { signatures: [{ protected: 'eyJhbGciOiJIUzI1NiJ9', header: 1.2 }] },
  { signatures: [{ protected: 'eyJhbGciOiJIUzI1NiJ9', header: 1n }] },
  { signatures: [{ protected: 'eyJhbGciOiJIUzI1NiJ9', header: 'a' }] },
  { signatures: [{ protected: 'eyJhbGciOiJIUzI1NiJ9', header: Symbol('a') }] },
  { signatures: [{ protected: 'eyJhbGciOiJIUzI1NiJ9', header: Buffer }] },
  { signatures: [{ protected: 'eyJhbGciOiJIUzI1NiJ9', header: Buffer.alloc(1) }] },
  { signatures: [{ protected: 'eyJhbGciOiJIUzI1NiJ9', header: () => 1 }] },
  { signatures: [{ protected: 'eyJhbGciOiJIUzI1NiJ9', header: [] }] },
  { signatures: [{ protected: 'eyJhbGciOiJIUzI1NiJ9', signature: undefined }] },
  { signatures: [{ protected: 'eyJhbGciOiJIUzI1NiJ9', signature: null }] },
  { signatures: [{ protected: 'eyJhbGciOiJIUzI1NiJ9', signature: true }] },
  { signatures: [{ protected: 'eyJhbGciOiJIUzI1NiJ9', signature: 1 }] },
  { signatures: [{ protected: 'eyJhbGciOiJIUzI1NiJ9', signature: 1.2 }] },
  { signatures: [{ protected: 'eyJhbGciOiJIUzI1NiJ9', signature: 1n }] },
  { signatures: [{ protected: 'eyJhbGciOiJIUzI1NiJ9', signature: Symbol('a') }] },
  { signatures: [{ protected: 'eyJhbGciOiJIUzI1NiJ9', signature: Buffer }] },
  { signatures: [{ protected: 'eyJhbGciOiJIUzI1NiJ9', signature: Buffer.alloc(1) }] },
  { signatures: [{ protected: 'eyJhbGciOiJIUzI1NiJ9', signature: () => 1 }] },
  { signatures: [{ protected: 'eyJhbGciOiJIUzI1NiJ9', signature: {} }] },
  { signatures: [{ protected: 'eyJhbGciOiJIUzI1NiJ9', signature: [] }] },
  { signatures: [{ protected: 'e30', header: {}, signature: '' }] },
  {
    signatures: [
      { protected: 'eyJhbGciOiJIUzI1NiJ9', signature: '' },
      { protected: 'eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19', signature: '' },
    ],
  },
];

describe('decode()', () => {
  const repeatedJoseHeaderToken: GeneralJsonWebSignatureToken = {
    payload: 'eyJpYXQiOiAxNzIzMDEwNDU1LCAic3ViIjogIjA3OEJXRERYYXNkY2c4In0',
    signatures: [
      {
        protected: 'eyJhbGciOiJIUzI1NiJ9',
        header: { alg: 'HS256' },
        signature: 'hRqmKz7sKWQZyNM1Kw9AgqPNOedszPvEADYmNFo8foA',
      },
    ],
  };

  const badUnprotectedTokenWithCritParameter: GeneralJsonWebSignatureToken = {
    payload: 'eyJpYXQiOiAxNzIzMDEwNDU1LCAic3ViIjogIjA3OEJXRERYYXNkY2c4In0',
    signatures: [
      {
        protected: 'eyJhbGciOiJIUzI1NiJ9',
        header: { crit: ['foo'], foo: 'foo' },
        signature: 'hRqmKz7sKWQZyNM1Kw9AgqPNOedszPvEADYmNFo8foA',
      },
    ],
  };

  const badUnprotectedTokenWithB64Parameter: GeneralJsonWebSignatureToken = {
    payload: 'eyJpYXQiOiAxNzIzMDEwNDU1LCAic3ViIjogIjA3OEJXRERYYXNkY2c4In0',
    signatures: [
      {
        protected: 'eyJhbGciOiJIUzI1NiJ9',
        header: { b64: false },
        signature: 'hRqmKz7sKWQZyNM1Kw9AgqPNOedszPvEADYmNFo8foA',
      },
    ],
  };

  const badTokenWithMismatchingB64Parameters: GeneralJsonWebSignatureToken = {
    payload: 'eyJpYXQiOiAxNzIzMDEwNDU1LCAic3ViIjogIjA3OEJXRERYYXNkY2c4In0',
    signatures: [
      {
        protected: 'eyJhbGciOiJIUzI1NiJ9',
        signature: 'hRqmKz7sKWQZyNM1Kw9AgqPNOedszPvEADYmNFo8foA',
      },
      {
        protected: 'eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19',
        signature: 'hRqmKz7sKWQZyNM1Kw9AgqPNOedszPvEADYmNFo8foA',
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

  const unencodedSignatureWithoutDot = Buffer.from('uXQJV7FqjHNukDJPwTa4wtywtIoQ9CiBf16ETgFeKjA', 'base64url');
  const unencodedSignatureWithDot = Buffer.from('Tb6KReuvHIM29TcHMTRZwMJAAs5zuCSX4gTMSplXjEs', 'base64url');
  const encodedProtectedSignature = Buffer.from('hRqmKz7sKWQZyNM1Kw9AgqPNOedszPvEADYmNFo8foA', 'base64url');
  const encodedUnprotectedSignature = Buffer.from('iRxcRLDYSMrd3ZlYZ_tUXP8pRAShmoErGTo4sEsew3U', 'base64url');

  it.each(invalidTokens)(
    'should throw when the provided General JSON Web Signature Token is invalid.',
    async (token) => {
      await expect(decode(token)).rejects.toThrowWithMessage(
        TypeError,
        'The provided General JSON Web Signature Token is invalid.',
      );
    },
  );

  it.each(invalidTokenFormats)(
    'should throw when the provided General JSON Web Signature Token has an invalid format.',
    async (token) => {
      await expect(decode(token)).rejects.toThrowWithMessage(
        InvalidJsonWebSignatureError,
        'The provided JSON Web Signature is invalid.',
      );
    },
  );

  it('should throw when there are repeated JSON Web Signature Header Parameters.', async () => {
    await expect(decode(repeatedJoseHeaderToken)).rejects.toThrowWithMessage(
      InvalidJsonWebSignatureError,
      'The provided JSON Web Signature is invalid.',
    );
  });

  it('should throw if the JOSE Header Parameter "crit" is present in the Unprotected Header.', async () => {
    await expect(decode(badUnprotectedTokenWithCritParameter)).rejects.toThrowWithMessage(
      InvalidJsonWebSignatureError,
      'The provided JSON Web Signature is invalid.',
    );
  });

  it('should throw if the JOSE Header Parameter "b64" is present in the Unprotected Header.', async () => {
    await expect(decode(badUnprotectedTokenWithB64Parameter)).rejects.toThrowWithMessage(
      InvalidJsonWebSignatureError,
      'The provided JSON Web Signature is invalid.',
    );
  });

  it('should throw when the JSON Web Signature Headers Parameter "b64" mismatch.', async () => {
    await expect(decode(badTokenWithMismatchingB64Parameters)).rejects.toThrowWithMessage(
      InvalidJsonWebSignatureError,
      'The provided JSON Web Signature is invalid.',
    );
  });

  it('should return the General JSON Web Signature Parameters from a Protected Attached Unencoded General JSON Web Signature Token without a dot.', async () => {
    await expect(
      decode(unencodedProtectedAttachedTokenWithoutDot),
    ).resolves.toStrictEqual<GeneralJsonWebSignatureParameters>({
      payload: payloadWithoutDot,
      signatures: [
        {
          protectedHeader: unencodedProtectedHeader,
          header: new JsonWebSignatureHeader(unencodedProtectedHeader as JsonWebSignatureHeaderParameters),
          signature: unencodedSignatureWithoutDot,
        },
      ],
    });
  });

  it('should return the General JSON Web Signature Parameters from a Protected Attached Unencoded General JSON Web Signature Token without a dot that is missing the JOSE Header Parameter "b64".', async () => {
    await expect(
      decode(missingUnencodedProtectedAttachedTokenWithoutDot),
    ).resolves.toStrictEqual<GeneralJsonWebSignatureParameters>({
      payload: expect.not.stringContaining(payloadWithoutDot.toString('utf8')),
      signatures: [
        {
          protectedHeader: encodedProtectedHeader,
          header: new JsonWebSignatureHeader(encodedProtectedHeader as JsonWebSignatureHeaderParameters),
          signature: unencodedSignatureWithoutDot,
        },
      ],
    });
  });

  it('should throw when providing an Unprotected Attached Unencoded General JSON Web Signature Token without a dot.', async () => {
    await expect(decode(badUnencodedUnprotectedAttachedTokenWithoutDot)).rejects.toThrowWithMessage(
      InvalidJsonWebSignatureError,
      'The provided JSON Web Signature is invalid.',
    );
  });

  it('should return the General JSON Web Signature Parameters from an Unprotected Attached Unencoded General JSON Web Signature Token without a dot that is missing the JOSE Header Parameter "b64".', async () => {
    await expect(
      decode(missingUnencodedUnprotectedAttachedTokenWithoutDot),
    ).resolves.toStrictEqual<GeneralJsonWebSignatureParameters>({
      payload: expect.not.stringContaining(payloadWithoutDot.toString('utf8')),
      signatures: [
        {
          unprotectedHeader: { ...encodedProtectedHeader, ...unprotectedHeader },
          header: new JsonWebSignatureHeader({
            ...encodedProtectedHeader,
            ...unprotectedHeader,
          } as JsonWebSignatureHeaderParameters),
          signature: unencodedSignatureWithoutDot,
        },
      ],
    });
  });

  it('should return the General JSON Web Signature Parameters from a Protected and Unprotected Attached Unencoded General JSON Web Signature Token without a dot.', async () => {
    await expect(
      decode(unencodedFullAttachedTokenWithoutDot),
    ).resolves.toStrictEqual<GeneralJsonWebSignatureParameters>({
      payload: payloadWithoutDot,
      signatures: [
        {
          protectedHeader: unencodedProtectedHeader,
          unprotectedHeader,
          header: new JsonWebSignatureHeader({
            ...unencodedProtectedHeader,
            ...unprotectedHeader,
          } as JsonWebSignatureHeaderParameters),
          signature: unencodedSignatureWithoutDot,
        },
      ],
    });
  });

  it('should throw when providing a Protected and Unprotected Attached Unencoded General JSON Web Signature Token without a dot where the JOSE Header Parameter "b64" is in the Unprotected Header.', async () => {
    await expect(decode(badUnencodedFullAttachedTokenWithoutDot)).rejects.toThrowWithMessage(
      InvalidJsonWebSignatureError,
      'The provided JSON Web Signature is invalid.',
    );
  });

  it('should return the General JSON Web Signature Parameters from a Protected and Unprotected Attached Unencoded General JSON Web Signature Token without a dot that is missing the JOSE Header Parameter "b64".', async () => {
    await expect(
      decode(missingUnencodedFullAttachedTokenWithoutDot),
    ).resolves.toStrictEqual<GeneralJsonWebSignatureParameters>({
      payload: expect.not.stringContaining(payloadWithoutDot.toString('utf8')),
      signatures: [
        {
          protectedHeader: encodedProtectedHeader,
          unprotectedHeader,
          header: new JsonWebSignatureHeader({
            ...encodedProtectedHeader,
            ...unprotectedHeader,
          } as JsonWebSignatureHeaderParameters),
          signature: unencodedSignatureWithoutDot,
        },
      ],
    });
  });

  it('should return the General JSON Web Signature Parameters from a Protected Detached Unencoded General JSON Web Signature Token without a dot.', async () => {
    await expect(
      decode(unencodedProtectedDetachedTokenWithoutDot),
    ).resolves.toStrictEqual<GeneralJsonWebSignatureParameters>({
      signatures: [
        {
          protectedHeader: unencodedProtectedHeader,
          header: new JsonWebSignatureHeader(unencodedProtectedHeader as JsonWebSignatureHeaderParameters),
          signature: unencodedSignatureWithoutDot,
        },
      ],
    });
  });

  it('should return the General JSON Web Signature Parameters from a Protected Detached Unencoded General JSON Web Signature Token without a dot that is missing the JOSE Header Parameter "b64".', async () => {
    await expect(
      decode(missingUnencodedProtectedDetachedTokenWithoutDot),
    ).resolves.toStrictEqual<GeneralJsonWebSignatureParameters>({
      signatures: [
        {
          protectedHeader: encodedProtectedHeader,
          header: new JsonWebSignatureHeader(encodedProtectedHeader as JsonWebSignatureHeaderParameters),
          signature: unencodedSignatureWithoutDot,
        },
      ],
    });
  });

  it('should throw when providing an Unprotected Detached Unencoded General JSON Web Signature Token without a dot where the JOSE Header Parameter "b64" is in the Unprotected Header.', async () => {
    await expect(decode(badUnencodedUnprotectedDetachedTokenWithoutDot)).rejects.toThrowWithMessage(
      InvalidJsonWebSignatureError,
      'The provided JSON Web Signature is invalid.',
    );
  });

  it('should return the General JSON Web Signature Parameters from an Unprotected Detached Unencoded General JSON Web Signature Token without a dot that is missing the JOSE Header Parameter "b64".', async () => {
    await expect(
      decode(missingUnencodedUnprotectedDetachedTokenWithoutDot),
    ).resolves.toStrictEqual<GeneralJsonWebSignatureParameters>({
      signatures: [
        {
          unprotectedHeader: { ...encodedProtectedHeader, ...unprotectedHeader },
          header: new JsonWebSignatureHeader({
            ...encodedProtectedHeader,
            ...unprotectedHeader,
          } as JsonWebSignatureHeaderParameters),
          signature: unencodedSignatureWithoutDot,
        },
      ],
    });
  });

  it('should return the General JSON Web Signature Parameters from a Protected and Unprotected Detached Unencoded General JSON Web Signature Token without a dot.', async () => {
    await expect(
      decode(unencodedFullDetachedTokenWithoutDot),
    ).resolves.toStrictEqual<GeneralJsonWebSignatureParameters>({
      signatures: [
        {
          protectedHeader: unencodedProtectedHeader,
          unprotectedHeader,
          header: new JsonWebSignatureHeader({
            ...unencodedProtectedHeader,
            ...unprotectedHeader,
          } as JsonWebSignatureHeaderParameters),
          signature: unencodedSignatureWithoutDot,
        },
      ],
    });
  });

  it('should throw when providing a Protected and Unprotected Detached Unencoded General JSON Web Signature Token without a dot where the JOSE Header Parameter "b64" is in the Unprotected Header.', async () => {
    await expect(decode(badUnencodedFullDetachedTokenWithoutDot)).rejects.toThrowWithMessage(
      InvalidJsonWebSignatureError,
      'The provided JSON Web Signature is invalid.',
    );
  });

  it('should return the General JSON Web Signature Parameters from a Protected and Unprotected Detached Unencoded General JSON Web Signature Token without a dot that is missing the JOSE Header Parameter "b64".', async () => {
    await expect(
      decode(missingUnencodedFullDetachedTokenWithoutDot),
    ).resolves.toStrictEqual<GeneralJsonWebSignatureParameters>({
      signatures: [
        {
          protectedHeader: encodedProtectedHeader,
          unprotectedHeader,
          header: new JsonWebSignatureHeader({
            ...encodedProtectedHeader,
            ...unprotectedHeader,
          } as JsonWebSignatureHeaderParameters),
          signature: unencodedSignatureWithoutDot,
        },
      ],
    });
  });

  it('should return the General JSON Web Signature Parameters from a Protected Detached Unencoded General JSON Web Signature Token with a dot.', async () => {
    await expect(
      decode(unencodedProtectedDetachedTokenWithDot),
    ).resolves.toStrictEqual<GeneralJsonWebSignatureParameters>({
      signatures: [
        {
          protectedHeader: unencodedProtectedHeader,
          header: new JsonWebSignatureHeader(unencodedProtectedHeader as JsonWebSignatureHeaderParameters),
          signature: unencodedSignatureWithDot,
        },
      ],
    });
  });

  it('should return the General JSON Web Signature Parameters from a Protected Detached Unencoded General JSON Web Signature Token with a dot that is missing the JOSE Header Parameter "b64".', async () => {
    await expect(
      decode(missingUnencodedProtectedDetachedTokenWithDot),
    ).resolves.toStrictEqual<GeneralJsonWebSignatureParameters>({
      signatures: [
        {
          protectedHeader: encodedProtectedHeader,
          header: new JsonWebSignatureHeader(encodedProtectedHeader as JsonWebSignatureHeaderParameters),
          signature: unencodedSignatureWithDot,
        },
      ],
    });
  });

  it('should throw when providing an Unprotected Detached Unencoded General JSON Web Signature Token with a dot where the JOSE Header Parameter "b64" is in the Unprotected Header.', async () => {
    await expect(decode(badUnencodedUnprotectedDetachedTokenWithDot)).rejects.toThrowWithMessage(
      InvalidJsonWebSignatureError,
      'The provided JSON Web Signature is invalid.',
    );
  });

  it('should return the General JSON Web Signature Parameters from an Unprotected Detached Unencoded General JSON Web Signature Token with a dot that is missing the JOSE Header Parameter "b64".', async () => {
    await expect(
      decode(missingUnencodedUnprotectedDetachedTokenWithDot),
    ).resolves.toStrictEqual<GeneralJsonWebSignatureParameters>({
      signatures: [
        {
          unprotectedHeader: { ...encodedProtectedHeader, ...unprotectedHeader },
          header: new JsonWebSignatureHeader({
            ...encodedProtectedHeader,
            ...unprotectedHeader,
          } as JsonWebSignatureHeaderParameters),
          signature: unencodedSignatureWithDot,
        },
      ],
    });
  });

  it('should return the General JSON Web Signature Parameters from a Protected and Unprotected Detached Unencoded General JSON Web Signature Token with a dot.', async () => {
    await expect(decode(unencodedFullDetachedTokenWithDot)).resolves.toStrictEqual<GeneralJsonWebSignatureParameters>({
      signatures: [
        {
          protectedHeader: unencodedProtectedHeader,
          unprotectedHeader,
          header: new JsonWebSignatureHeader({
            ...unencodedProtectedHeader,
            ...unprotectedHeader,
          } as JsonWebSignatureHeaderParameters),
          signature: unencodedSignatureWithDot,
        },
      ],
    });
  });

  it('should throw when providing a Protected and Unprotected Detached Unencoded General JSON Web Signature Token with a dot where the JOSE Header Parameter "b64" is in the Unprotected Header.', async () => {
    await expect(decode(badUnencodedFullDetachedTokenWithDot)).rejects.toThrowWithMessage(
      InvalidJsonWebSignatureError,
      'The provided JSON Web Signature is invalid.',
    );
  });

  it('should return the General JSON Web Signature Parameters from a Protected and Unprotected Detached Unencoded General JSON Web Signature Token with a dot that is missing the JOSE Header Parameter "b64".', async () => {
    await expect(
      decode(missingUnencodedFullDetachedTokenWithDot),
    ).resolves.toStrictEqual<GeneralJsonWebSignatureParameters>({
      signatures: [
        {
          protectedHeader: encodedProtectedHeader,
          unprotectedHeader,
          header: new JsonWebSignatureHeader({
            ...encodedProtectedHeader,
            ...unprotectedHeader,
          } as JsonWebSignatureHeaderParameters),
          signature: unencodedSignatureWithDot,
        },
      ],
    });
  });

  it('should return the General JSON Web Signature Parameters from a Protected Attached Encoded General JSON Web Signature Token without a dot.', async () => {
    await expect(decode(encodedProtectedAttachedToken)).resolves.toStrictEqual<GeneralJsonWebSignatureParameters>({
      payload: payloadWithoutDot,
      signatures: [
        {
          protectedHeader: encodedProtectedHeader,
          header: new JsonWebSignatureHeader(encodedProtectedHeader as JsonWebSignatureHeaderParameters),
          signature: encodedProtectedSignature,
        },
      ],
    });
  });

  it('should return the General JSON Web Signature Parameters from an Unprotected Attached Encoded General JSON Web Signature Token without a dot.', async () => {
    await expect(decode(encodedUnprotectedAttachedToken)).resolves.toStrictEqual<GeneralJsonWebSignatureParameters>({
      payload: payloadWithoutDot,
      signatures: [
        {
          unprotectedHeader: { ...encodedProtectedHeader, ...unprotectedHeader },
          header: new JsonWebSignatureHeader({
            ...encodedProtectedHeader,
            ...unprotectedHeader,
          } as JsonWebSignatureHeaderParameters),
          signature: encodedUnprotectedSignature,
        },
      ],
    });
  });

  it('should return the General JSON Web Signature Parameters from a Protected and Unprotected Attached Encoded General JSON Web Signature Token without a dot.', async () => {
    await expect(decode(encodedFullAttachedToken)).resolves.toStrictEqual<GeneralJsonWebSignatureParameters>({
      payload: payloadWithoutDot,
      signatures: [
        {
          protectedHeader: encodedProtectedHeader,
          unprotectedHeader,
          header: new JsonWebSignatureHeader({
            ...encodedProtectedHeader,
            ...unprotectedHeader,
          } as JsonWebSignatureHeaderParameters),
          signature: encodedProtectedSignature,
        },
      ],
    });
  });

  it('should return the General JSON Web Signature Parameters from a Protected Detached Encoded General JSON Web Signature Token without a dot.', async () => {
    await expect(decode(encodedProtectedDetachedToken)).resolves.toStrictEqual<GeneralJsonWebSignatureParameters>({
      signatures: [
        {
          protectedHeader: encodedProtectedHeader,
          header: new JsonWebSignatureHeader(encodedProtectedHeader as JsonWebSignatureHeaderParameters),
          signature: encodedProtectedSignature,
        },
      ],
    });
  });

  it('should return the General JSON Web Signature Parameters from an Unprotected Detached Encoded General JSON Web Signature Token without a dot.', async () => {
    await expect(decode(encodedUnprotectedDetachedToken)).resolves.toStrictEqual<GeneralJsonWebSignatureParameters>({
      signatures: [
        {
          unprotectedHeader: { ...encodedProtectedHeader, ...unprotectedHeader },
          header: new JsonWebSignatureHeader({
            ...encodedProtectedHeader,
            ...unprotectedHeader,
          } as JsonWebSignatureHeaderParameters),
          signature: encodedUnprotectedSignature,
        },
      ],
    });
  });

  it('should return the General JSON Web Signature Parameters from a Protected and Unprotected Detached Encoded General JSON Web Signature Token without a dot.', async () => {
    await expect(decode(encodedFullDetachedToken)).resolves.toStrictEqual<GeneralJsonWebSignatureParameters>({
      signatures: [
        {
          protectedHeader: encodedProtectedHeader,
          unprotectedHeader,
          header: new JsonWebSignatureHeader({
            ...encodedProtectedHeader,
            ...unprotectedHeader,
          } as JsonWebSignatureHeaderParameters),
          signature: encodedProtectedSignature,
        },
      ],
    });
  });
});
