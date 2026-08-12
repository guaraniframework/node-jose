import { Buffer } from 'buffer';

import { InvalidJsonWebSignatureError } from '../../../errors/invalid-jsonwebsignature.error';
import { JsonWebSignatureHeader } from '../../jsonwebsignature-header';
import { JsonWebSignatureHeaderParameters } from '../../jsonwebsignature-header.parameters';
import { CompactJsonWebSignatureParameters } from './compact-jsonwebsignature.parameters';
import { decode } from './decode';

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

const invalidTokenFormats = ['a', '.a', 'a.b', 'a.b.c.d'];

describe('decode()', () => {
  const headerlessToken =
    '.eyJpYXQiOiAxNzIzMDEwNDU1LCAic3ViIjogIjA3OEJXRERYYXNkY2c4In0.hRqmKz7sKWQZyNM1Kw9AgqPNOedszPvEADYmNFo8foA';

  const invalidHeaderToken =
    'e30.eyJpYXQiOiAxNzIzMDEwNDU1LCAic3ViIjogIjA3OEJXRERYYXNkY2c4In0.hRqmKz7sKWQZyNM1Kw9AgqPNOedszPvEADYmNFo8foA';

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

  const unencodedSignatureWithoutDot = Buffer.from('uXQJV7FqjHNukDJPwTa4wtywtIoQ9CiBf16ETgFeKjA', 'base64url');
  const unencodedSignatureWithDot = Buffer.from('A5dxf2s96_n5FLueVuW1Z_vh161FwXZC4YLPff6dmDY', 'base64url');
  const encodedSignature = Buffer.from('hRqmKz7sKWQZyNM1Kw9AgqPNOedszPvEADYmNFo8foA', 'base64url');

  it.each(invalidTokens)(
    'should throw when the provided Compact JSON Web Signature Token is invalid.',
    async (token) => {
      await expect(decode(token)).rejects.toThrowWithMessage(
        TypeError,
        'The provided Compact JSON Web Signature Token is invalid.',
      );
    },
  );

  it.each(invalidTokenFormats)(
    'should throw when the provided Compact JSON Web Signature Token has an invalid format.',
    async (token) => {
      await expect(decode(token)).rejects.toThrowWithMessage(
        InvalidJsonWebSignatureError,
        'The provided JSON Web Signature is invalid.',
      );
    },
  );

  it('should throw when failing to parse the Protected Header of the provided Compact JSON Web Signature Token.', async () => {
    await expect(decode(headerlessToken)).rejects.toThrowWithMessage(
      InvalidJsonWebSignatureError,
      'The provided JSON Web Signature is invalid.',
    );
  });

  it('should throw when the Protected Header of the provided Compact JSON Web Signature Token is invalid.', async () => {
    await expect(decode(invalidHeaderToken)).rejects.toThrowWithMessage(
      InvalidJsonWebSignatureError,
      'The provided JSON Web Signature is invalid.',
    );
  });

  it('should return the Compact JSON Web Signature Parameters from an Attached Unencoded Compact JSON Web Signature Token without a dot.', async () => {
    await expect(decode(unencodedAttachedTokenWithoutDot)).resolves.toStrictEqual<CompactJsonWebSignatureParameters>({
      protectedHeader: new JsonWebSignatureHeader(unencodedProtectedHeader),
      payload: payloadWithoutDot,
      signature: unencodedSignatureWithoutDot,
    });
  });

  it('should return the Compact JSON Web Signature Parameters from a Detached Unencoded Compact JSON Web Signature Token without a dot.', async () => {
    await expect(decode(unencodedDetachedTokenWithoutDot)).resolves.toStrictEqual<CompactJsonWebSignatureParameters>({
      protectedHeader: new JsonWebSignatureHeader(unencodedProtectedHeader),
      signature: unencodedSignatureWithoutDot,
    });
  });

  it('should return the Compact JSON Web Signature Parameters from a Detached Unencoded Compact JSON Web Signature Token with a dot.', async () => {
    await expect(decode(unencodedDetachedTokenWithDot)).resolves.toStrictEqual<CompactJsonWebSignatureParameters>({
      protectedHeader: new JsonWebSignatureHeader(unencodedProtectedHeader),
      signature: unencodedSignatureWithDot,
    });
  });

  it('should return the Compact JSON Web Signature Parameters from an Attached Encoded Compact JSON Web Signature Token.', async () => {
    await expect(decode(encodedAttachedToken)).resolves.toStrictEqual<CompactJsonWebSignatureParameters>({
      protectedHeader: new JsonWebSignatureHeader(encodedProtectedHeader),
      payload: payloadWithoutDot,
      signature: encodedSignature,
    });
  });

  it('should return the Compact JSON Web Signature Parameters from a Detached Encoded Compact JSON Web Signature Token.', async () => {
    await expect(decode(encodedDetachedToken)).resolves.toStrictEqual<CompactJsonWebSignatureParameters>({
      protectedHeader: new JsonWebSignatureHeader(encodedProtectedHeader),
      signature: encodedSignature,
    });
  });
});
