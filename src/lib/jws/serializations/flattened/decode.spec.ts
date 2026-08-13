import { Buffer } from 'buffer';

import { jsonStringify } from '@guarani/primitives';

import { InvalidJsonWebSignatureError } from '../../../errors/invalid-jsonwebsignature.error';
import { JsonWebSignatureHeader } from '../../jsonwebsignature-header';
import { JsonWebSignatureHeaderParameters } from '../../jsonwebsignature-header.parameters';
import { decode } from './decode';
import { FlattenedJsonWebSignatureParameters } from './flattened-jsonwebsignature.parameters';
import { FlattenedJsonWebSignatureToken } from './flattened-jsonwebsignature.token';

const invalidTokens: any[] = [undefined, null, true, 1, 1.2, 1n, Symbol('a'), Buffer, Buffer.alloc(1), () => 1, []];

const invalidTokenFormats: any[] = [
  {},
  { protected: undefined },
  { protected: null },
  { protected: true },
  { protected: 1 },
  { protected: 1.2 },
  { protected: 1n },
  { protected: Symbol('a') },
  { protected: Buffer },
  { protected: Buffer.alloc(1) },
  { protected: () => 1 },
  { protected: {} },
  { protected: [] },
  { protected: '' },
  { protected: 'eyJhbGciOiJIUzI1NiJ9', header: undefined },
  { protected: 'eyJhbGciOiJIUzI1NiJ9', header: null },
  { protected: 'eyJhbGciOiJIUzI1NiJ9', header: true },
  { protected: 'eyJhbGciOiJIUzI1NiJ9', header: 1 },
  { protected: 'eyJhbGciOiJIUzI1NiJ9', header: 1.2 },
  { protected: 'eyJhbGciOiJIUzI1NiJ9', header: 1n },
  { protected: 'eyJhbGciOiJIUzI1NiJ9', header: 'a' },
  { protected: 'eyJhbGciOiJIUzI1NiJ9', header: Symbol('a') },
  { protected: 'eyJhbGciOiJIUzI1NiJ9', header: Buffer },
  { protected: 'eyJhbGciOiJIUzI1NiJ9', header: Buffer.alloc(1) },
  { protected: 'eyJhbGciOiJIUzI1NiJ9', header: () => 1 },
  { protected: 'eyJhbGciOiJIUzI1NiJ9', header: [] },
  { protected: 'eyJhbGciOiJIUzI1NiJ9', payload: undefined },
  { protected: 'eyJhbGciOiJIUzI1NiJ9', payload: null },
  { protected: 'eyJhbGciOiJIUzI1NiJ9', payload: true },
  { protected: 'eyJhbGciOiJIUzI1NiJ9', payload: 1 },
  { protected: 'eyJhbGciOiJIUzI1NiJ9', payload: 1.2 },
  { protected: 'eyJhbGciOiJIUzI1NiJ9', payload: 1n },
  { protected: 'eyJhbGciOiJIUzI1NiJ9', payload: Symbol('a') },
  { protected: 'eyJhbGciOiJIUzI1NiJ9', payload: Buffer },
  { protected: 'eyJhbGciOiJIUzI1NiJ9', payload: Buffer.alloc(1) },
  { protected: 'eyJhbGciOiJIUzI1NiJ9', payload: () => 1 },
  { protected: 'eyJhbGciOiJIUzI1NiJ9', payload: {} },
  { protected: 'eyJhbGciOiJIUzI1NiJ9', payload: [] },
  { protected: 'eyJhbGciOiJIUzI1NiJ9', payload: '' },
  { protected: 'eyJhbGciOiJIUzI1NiJ9', signature: undefined },
  { protected: 'eyJhbGciOiJIUzI1NiJ9', signature: null },
  { protected: 'eyJhbGciOiJIUzI1NiJ9', signature: true },
  { protected: 'eyJhbGciOiJIUzI1NiJ9', signature: 1 },
  { protected: 'eyJhbGciOiJIUzI1NiJ9', signature: 1.2 },
  { protected: 'eyJhbGciOiJIUzI1NiJ9', signature: 1n },
  { protected: 'eyJhbGciOiJIUzI1NiJ9', signature: Symbol('a') },
  { protected: 'eyJhbGciOiJIUzI1NiJ9', signature: Buffer },
  { protected: 'eyJhbGciOiJIUzI1NiJ9', signature: Buffer.alloc(1) },
  { protected: 'eyJhbGciOiJIUzI1NiJ9', signature: () => 1 },
  { protected: 'eyJhbGciOiJIUzI1NiJ9', signature: {} },
  { protected: 'eyJhbGciOiJIUzI1NiJ9', signature: [] },
  { protected: 'e30', header: {}, signature: '' },
];

describe('decode()', () => {
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

  const unencodedSignatureWithoutDot = Buffer.from('uXQJV7FqjHNukDJPwTa4wtywtIoQ9CiBf16ETgFeKjA', 'base64url');
  const unencodedSignatureWithDot = Buffer.from('Tb6KReuvHIM29TcHMTRZwMJAAs5zuCSX4gTMSplXjEs', 'base64url');
  const encodedProtectedSignature = Buffer.from('hRqmKz7sKWQZyNM1Kw9AgqPNOedszPvEADYmNFo8foA', 'base64url');
  const encodedUnprotectedSignature = Buffer.from('iRxcRLDYSMrd3ZlYZ_tUXP8pRAShmoErGTo4sEsew3U', 'base64url');

  it.each(invalidTokens)(
    'should throw when the provided Flattened JSON Web Signature Token is invalid.',
    async (token) => {
      await expect(decode(token)).rejects.toThrowWithMessage(
        TypeError,
        'The provided Flattened JSON Web Signature Token is invalid.',
      );
    },
  );

  it.each(invalidTokenFormats)(
    'should throw when the provided Flattened JSON Web Signature Token has an invalid format.',
    async (token) => {
      await expect(decode(token)).rejects.toThrowWithMessage(
        InvalidJsonWebSignatureError,
        'The provided JSON Web Signature is invalid.',
      );
    },
  );

  it('should throw when there are repeated JSON Web Signature Header Parameters.', async () => {
    await expect(
      decode({
        ...encodedProtectedAttachedToken,
        protected: Buffer.from(jsonStringify(encodedProtectedHeader), 'utf8').toString('base64url'),
        header: encodedProtectedHeader,
      }),
    ).rejects.toThrowWithMessage(InvalidJsonWebSignatureError, 'The provided JSON Web Signature is invalid.');
  });

  it('should throw if the JOSE Header Parameter "crit" is present in the Unprotected Header.', async () => {
    await expect(
      decode({
        ...encodedProtectedAttachedToken,
        protected: Buffer.from(jsonStringify({ alg: 'HS256' }), 'utf8').toString('base64url'),
        header: { crit: ['foo'], foo: 'foo' },
      }),
    ).rejects.toThrowWithMessage(InvalidJsonWebSignatureError, 'The provided JSON Web Signature is invalid.');
  });

  it('should throw if the JOSE Header Parameter "b64" is present in the Unprotected Header.', async () => {
    await expect(
      decode({
        ...encodedProtectedAttachedToken,
        protected: Buffer.from(jsonStringify({ alg: 'HS256' }), 'utf8').toString('base64url'),
        header: { b64: false },
      }),
    ).rejects.toThrowWithMessage(InvalidJsonWebSignatureError, 'The provided JSON Web Signature is invalid.');
  });

  it('should return the Flattened JSON Web Signature Parameters from a Protected Attached Unencoded Flattened JSON Web Signature Token without a dot.', async () => {
    await expect(
      decode(unencodedProtectedAttachedTokenWithoutDot),
    ).resolves.toStrictEqual<FlattenedJsonWebSignatureParameters>({
      protectedHeader: unencodedProtectedHeader,
      header: new JsonWebSignatureHeader(unencodedProtectedHeader as JsonWebSignatureHeaderParameters),
      payload: payloadWithoutDot,
      signature: unencodedSignatureWithoutDot,
    });
  });

  it('should return the Flattened JSON Web Signature Parameters from a Protected Attached Unencoded Flattened JSON Web Signature Token without a dot that is missing the JOSE Header Parameter "b64".', async () => {
    await expect(
      decode(missingUnencodedProtectedAttachedTokenWithoutDot),
    ).resolves.toStrictEqual<FlattenedJsonWebSignatureParameters>({
      protectedHeader: encodedProtectedHeader,
      header: new JsonWebSignatureHeader(encodedProtectedHeader as JsonWebSignatureHeaderParameters),
      payload: expect.not.stringContaining(payloadWithoutDot.toString('utf8')),
      signature: unencodedSignatureWithoutDot,
    });
  });

  it('should throw when providing an Unprotected Attached Unencoded Flattened JSON Web Signature Token without a dot.', async () => {
    await expect(decode(badUnencodedUnprotectedAttachedTokenWithoutDot)).rejects.toThrowWithMessage(
      InvalidJsonWebSignatureError,
      'The provided JSON Web Signature is invalid.',
    );
  });

  it('should return the Flattened JSON Web Signature Parameters from an Unprotected Attached Unencoded Flattened JSON Web Signature Token without a dot that is missing the JOSE Header Parameter "b64".', async () => {
    await expect(
      decode(missingUnencodedUnprotectedAttachedTokenWithoutDot),
    ).resolves.toStrictEqual<FlattenedJsonWebSignatureParameters>({
      unprotectedHeader: { ...encodedProtectedHeader, ...unprotectedHeader },
      header: new JsonWebSignatureHeader({
        ...encodedProtectedHeader,
        ...unprotectedHeader,
      } as JsonWebSignatureHeaderParameters),
      payload: expect.not.stringContaining(payloadWithoutDot.toString('utf8')),
      signature: unencodedSignatureWithoutDot,
    });
  });

  it('should return the Flattened JSON Web Signature Parameters from a Protected and Unprotected Attached Unencoded Flattened JSON Web Signature Token without a dot.', async () => {
    await expect(
      decode(unencodedFullAttachedTokenWithoutDot),
    ).resolves.toStrictEqual<FlattenedJsonWebSignatureParameters>({
      protectedHeader: unencodedProtectedHeader,
      unprotectedHeader,
      header: new JsonWebSignatureHeader({
        ...unencodedProtectedHeader,
        ...unprotectedHeader,
      } as JsonWebSignatureHeaderParameters),
      payload: payloadWithoutDot,
      signature: unencodedSignatureWithoutDot,
    });
  });

  it('should throw when providing a Protected and Unprotected Attached Unencoded Flattened JSON Web Signature Token without a dot where the JOSE Header Parameter "b64" is in the Unprotected Header.', async () => {
    await expect(decode(badUnencodedFullAttachedTokenWithoutDot)).rejects.toThrowWithMessage(
      InvalidJsonWebSignatureError,
      'The provided JSON Web Signature is invalid.',
    );
  });

  it('should return the Flattened JSON Web Signature Parameters from a Protected and Unprotected Attached Unencoded Flattened JSON Web Signature Token without a dot that is missing the JOSE Header Parameter "b64".', async () => {
    await expect(
      decode(missingUnencodedFullAttachedTokenWithoutDot),
    ).resolves.toStrictEqual<FlattenedJsonWebSignatureParameters>({
      protectedHeader: encodedProtectedHeader,
      unprotectedHeader,
      header: new JsonWebSignatureHeader({
        ...encodedProtectedHeader,
        ...unprotectedHeader,
      } as JsonWebSignatureHeaderParameters),
      payload: expect.not.stringContaining(payloadWithoutDot.toString('utf8')),
      signature: unencodedSignatureWithoutDot,
    });
  });

  it('should return the Flattened JSON Web Signature Parameters from a Protected Detached Unencoded Flattened JSON Web Signature Token without a dot.', async () => {
    await expect(
      decode(unencodedProtectedDetachedTokenWithoutDot),
    ).resolves.toStrictEqual<FlattenedJsonWebSignatureParameters>({
      protectedHeader: unencodedProtectedHeader,
      header: new JsonWebSignatureHeader(unencodedProtectedHeader as JsonWebSignatureHeaderParameters),
      signature: unencodedSignatureWithoutDot,
    });
  });

  it('should return the Flattened JSON Web Signature Parameters from a Protected Detached Unencoded Flattened JSON Web Signature Token without a dot that is missing the JOSE Header Parameter "b64".', async () => {
    await expect(
      decode(missingUnencodedProtectedDetachedTokenWithoutDot),
    ).resolves.toStrictEqual<FlattenedJsonWebSignatureParameters>({
      protectedHeader: encodedProtectedHeader,
      header: new JsonWebSignatureHeader(encodedProtectedHeader as JsonWebSignatureHeaderParameters),
      signature: unencodedSignatureWithoutDot,
    });
  });

  it('should throw when providing an Unprotected Detached Unencoded Flattened JSON Web Signature Token without a dot where the JOSE Header Parameter "b64" is in the Unprotected Header.', async () => {
    await expect(decode(badUnencodedUnprotectedDetachedTokenWithoutDot)).rejects.toThrowWithMessage(
      InvalidJsonWebSignatureError,
      'The provided JSON Web Signature is invalid.',
    );
  });

  it('should return the Flattened JSON Web Signature Parameters from an Unprotected Detached Unencoded Flattened JSON Web Signature Token without a dot that is missing the JOSE Header Parameter "b64".', async () => {
    await expect(
      decode(missingUnencodedUnprotectedDetachedTokenWithoutDot),
    ).resolves.toStrictEqual<FlattenedJsonWebSignatureParameters>({
      unprotectedHeader: { ...encodedProtectedHeader, ...unprotectedHeader },
      header: new JsonWebSignatureHeader({
        ...encodedProtectedHeader,
        ...unprotectedHeader,
      } as JsonWebSignatureHeaderParameters),
      signature: unencodedSignatureWithoutDot,
    });
  });

  it('should return the Flattened JSON Web Signature Parameters from a Protected and Unprotected Detached Unencoded Flattened JSON Web Signature Token without a dot.', async () => {
    await expect(
      decode(unencodedFullDetachedTokenWithoutDot),
    ).resolves.toStrictEqual<FlattenedJsonWebSignatureParameters>({
      protectedHeader: unencodedProtectedHeader,
      unprotectedHeader,
      header: new JsonWebSignatureHeader({
        ...unencodedProtectedHeader,
        ...unprotectedHeader,
      } as JsonWebSignatureHeaderParameters),
      signature: unencodedSignatureWithoutDot,
    });
  });

  it('should throw when providing a Protected and Unprotected Detached Unencoded Flattened JSON Web Signature Token without a dot where the JOSE Header Parameter "b64" is in the Unprotected Header.', async () => {
    await expect(decode(badUnencodedFullDetachedTokenWithoutDot)).rejects.toThrowWithMessage(
      InvalidJsonWebSignatureError,
      'The provided JSON Web Signature is invalid.',
    );
  });

  it('should return the Flattened JSON Web Signature Parameters from a Protected and Unprotected Detached Unencoded Flattened JSON Web Signature Token without a dot that is missing the JOSE Header Parameter "b64".', async () => {
    await expect(
      decode(missingUnencodedFullDetachedTokenWithoutDot),
    ).resolves.toStrictEqual<FlattenedJsonWebSignatureParameters>({
      protectedHeader: encodedProtectedHeader,
      unprotectedHeader,
      header: new JsonWebSignatureHeader({
        ...encodedProtectedHeader,
        ...unprotectedHeader,
      } as JsonWebSignatureHeaderParameters),
      signature: unencodedSignatureWithoutDot,
    });
  });

  it('should return the Flattened JSON Web Signature Parameters from a Protected Detached Unencoded Flattened JSON Web Signature Token with a dot.', async () => {
    await expect(
      decode(unencodedProtectedDetachedTokenWithDot),
    ).resolves.toStrictEqual<FlattenedJsonWebSignatureParameters>({
      protectedHeader: unencodedProtectedHeader,
      header: new JsonWebSignatureHeader(unencodedProtectedHeader as JsonWebSignatureHeaderParameters),
      signature: unencodedSignatureWithDot,
    });
  });

  it('should return the Flattened JSON Web Signature Parameters from a Protected Detached Unencoded Flattened JSON Web Signature Token with a dot that is missing the JOSE Header Parameter "b64".', async () => {
    await expect(
      decode(missingUnencodedProtectedDetachedTokenWithDot),
    ).resolves.toStrictEqual<FlattenedJsonWebSignatureParameters>({
      protectedHeader: encodedProtectedHeader,
      header: new JsonWebSignatureHeader(encodedProtectedHeader as JsonWebSignatureHeaderParameters),
      signature: unencodedSignatureWithDot,
    });
  });

  it('should throw when providing an Unprotected Detached Unencoded Flattened JSON Web Signature Token with a dot where the JOSE Header Parameter "b64" is in the Unprotected Header.', async () => {
    await expect(decode(badUnencodedUnprotectedDetachedTokenWithDot)).rejects.toThrowWithMessage(
      InvalidJsonWebSignatureError,
      'The provided JSON Web Signature is invalid.',
    );
  });

  it('should return the Flattened JSON Web Signature Parameters from an Unprotected Detached Unencoded Flattened JSON Web Signature Token with a dot that is missing the JOSE Header Parameter "b64".', async () => {
    await expect(
      decode(missingUnencodedUnprotectedDetachedTokenWithDot),
    ).resolves.toStrictEqual<FlattenedJsonWebSignatureParameters>({
      unprotectedHeader: { ...encodedProtectedHeader, ...unprotectedHeader },
      header: new JsonWebSignatureHeader({
        ...encodedProtectedHeader,
        ...unprotectedHeader,
      } as JsonWebSignatureHeaderParameters),
      signature: unencodedSignatureWithDot,
    });
  });

  it('should return the Flattened JSON Web Signature Parameters from a Protected and Unprotected Detached Unencoded Flattened JSON Web Signature Token with a dot.', async () => {
    await expect(decode(unencodedFullDetachedTokenWithDot)).resolves.toStrictEqual<FlattenedJsonWebSignatureParameters>(
      {
        protectedHeader: unencodedProtectedHeader,
        unprotectedHeader,
        header: new JsonWebSignatureHeader({
          ...unencodedProtectedHeader,
          ...unprotectedHeader,
        } as JsonWebSignatureHeaderParameters),
        signature: unencodedSignatureWithDot,
      },
    );
  });

  it('should throw when providing a Protected and Unprotected Detached Unencoded Flattened JSON Web Signature Token with a dot where the JOSE Header Parameter "b64" is in the Unprotected Header.', async () => {
    await expect(decode(badUnencodedFullDetachedTokenWithDot)).rejects.toThrowWithMessage(
      InvalidJsonWebSignatureError,
      'The provided JSON Web Signature is invalid.',
    );
  });

  it('should return the Flattened JSON Web Signature Parameters from a Protected and Unprotected Detached Unencoded Flattened JSON Web Signature Token with a dot that is missing the JOSE Header Parameter "b64".', async () => {
    await expect(
      decode(missingUnencodedFullDetachedTokenWithDot),
    ).resolves.toStrictEqual<FlattenedJsonWebSignatureParameters>({
      protectedHeader: encodedProtectedHeader,
      unprotectedHeader,
      header: new JsonWebSignatureHeader({
        ...encodedProtectedHeader,
        ...unprotectedHeader,
      } as JsonWebSignatureHeaderParameters),
      signature: unencodedSignatureWithDot,
    });
  });

  it('should return the Flattened JSON Web Signature Parameters from a Protected Attached Encoded Flattened JSON Web Signature Token without a dot.', async () => {
    await expect(decode(encodedProtectedAttachedToken)).resolves.toStrictEqual<FlattenedJsonWebSignatureParameters>({
      protectedHeader: encodedProtectedHeader,
      header: new JsonWebSignatureHeader(encodedProtectedHeader as JsonWebSignatureHeaderParameters),
      payload: payloadWithoutDot,
      signature: encodedProtectedSignature,
    });
  });

  it('should return the Flattened JSON Web Signature Parameters from an Unprotected Attached Encoded Flattened JSON Web Signature Token without a dot.', async () => {
    await expect(decode(encodedUnprotectedAttachedToken)).resolves.toStrictEqual<FlattenedJsonWebSignatureParameters>({
      unprotectedHeader: { ...encodedProtectedHeader, ...unprotectedHeader },
      header: new JsonWebSignatureHeader({
        ...encodedProtectedHeader,
        ...unprotectedHeader,
      } as JsonWebSignatureHeaderParameters),
      payload: payloadWithoutDot,
      signature: encodedUnprotectedSignature,
    });
  });

  it('should return the Flattened JSON Web Signature Parameters from a Protected and Unprotected Attached Encoded Flattened JSON Web Signature Token without a dot.', async () => {
    await expect(decode(encodedFullAttachedToken)).resolves.toStrictEqual<FlattenedJsonWebSignatureParameters>({
      protectedHeader: encodedProtectedHeader,
      unprotectedHeader,
      header: new JsonWebSignatureHeader({
        ...encodedProtectedHeader,
        ...unprotectedHeader,
      } as JsonWebSignatureHeaderParameters),
      payload: payloadWithoutDot,
      signature: encodedProtectedSignature,
    });
  });

  it('should return the Flattened JSON Web Signature Parameters from a Protected Detached Encoded Flattened JSON Web Signature Token without a dot.', async () => {
    await expect(decode(encodedProtectedDetachedToken)).resolves.toStrictEqual<FlattenedJsonWebSignatureParameters>({
      protectedHeader: encodedProtectedHeader,
      header: new JsonWebSignatureHeader(encodedProtectedHeader as JsonWebSignatureHeaderParameters),
      signature: encodedProtectedSignature,
    });
  });

  it('should return the Flattened JSON Web Signature Parameters from an Unprotected Detached Encoded Flattened JSON Web Signature Token without a dot.', async () => {
    await expect(decode(encodedUnprotectedDetachedToken)).resolves.toStrictEqual<FlattenedJsonWebSignatureParameters>({
      unprotectedHeader: { ...encodedProtectedHeader, ...unprotectedHeader },
      header: new JsonWebSignatureHeader({
        ...encodedProtectedHeader,
        ...unprotectedHeader,
      } as JsonWebSignatureHeaderParameters),
      signature: encodedUnprotectedSignature,
    });
  });

  it('should return the Flattened JSON Web Signature Parameters from a Protected and Unprotected Detached Encoded Flattened JSON Web Signature Token without a dot.', async () => {
    await expect(decode(encodedFullDetachedToken)).resolves.toStrictEqual<FlattenedJsonWebSignatureParameters>({
      protectedHeader: encodedProtectedHeader,
      unprotectedHeader,
      header: new JsonWebSignatureHeader({
        ...encodedProtectedHeader,
        ...unprotectedHeader,
      } as JsonWebSignatureHeaderParameters),
      signature: encodedProtectedSignature,
    });
  });
});
