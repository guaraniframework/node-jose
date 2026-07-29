import { Buffer } from 'buffer';

import { InvalidJsonWebKeyError } from '../../../errors/invalid-jsonwebkey.error';
import { InvalidJsonWebSignatureError } from '../../../errors/invalid-jsonwebsignature.error';
import { OctetSequenceJsonWebKey } from '../../jwk/oct/octet-sequence.jsonwebkey';
import { NoneJsonWebSignatureDigitalSignatureBackend } from './none-jsonwebsignature-digital-signature.backend';

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
  new OctetSequenceJsonWebKey({ kty: 'oct', k: 'qDM80igvja4Tg_tNsEuWDhl2bMM6_NgJEldFhIEuwqQ' }),
];

describe('None JSON Web Signature Digital Signature Backend', () => {
  const message = Buffer.from('Super secret message.', 'utf8');

  describe('none', () => {
    const backend = new NoneJsonWebSignatureDigitalSignatureBackend();

    const jwk = null;
    const signature = Buffer.alloc(0);

    const wrongSignature = Buffer.from('oYyAwnx7D5WIo3L1WWx_zBSNX12nH8lwXQHgpPiApSk', 'base64url');

    describe('sign()', () => {
      it.each(invalidJsonWebKeys)(
        'should throw when the provided JSON Web Key cannot be used by the JSON Web Signature Algorithm.',
        async (jwk) => {
          await expect(backend.sign(message, jwk)).rejects.toThrowWithMessage(
            InvalidJsonWebKeyError,
            'The provided JSON Web Key cannot be used by the JSON Web Signature Algorithm.',
          );
        },
      );

      it('should sign the provided Message.', async () => {
        await expect(backend.sign(message, jwk)).resolves.toStrictEqual(signature);
      });
    });

    describe('verify()', () => {
      it.each(invalidJsonWebKeys)(
        'should throw when the provided JSON Web Key cannot be used by the JSON Web Signature Algorithm.',
        async (jwk) => {
          await expect(backend.verify(signature, message, jwk)).rejects.toThrowWithMessage(
            InvalidJsonWebKeyError,
            'The provided JSON Web Key cannot be used by the JSON Web Signature Algorithm.',
          );
        },
      );

      it('should throw when the provided Signature is invalid.', async () => {
        await expect(backend.verify(wrongSignature, message, jwk)).rejects.toThrowWithMessage(
          InvalidJsonWebSignatureError,
          'The provided JSON Web Signature is invalid.',
        );
      });

      it('should not throw when the provided Signature matches the provided Message.', async () => {
        await expect(backend.verify(signature, message, jwk)).resolves.not.toThrow();
      });
    });
  });
});
