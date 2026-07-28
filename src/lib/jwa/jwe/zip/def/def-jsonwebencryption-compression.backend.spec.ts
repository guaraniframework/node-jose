import { Buffer } from 'buffer';

import { DEFJsonWebEncryptionCompressionBackend } from './def-jsonwebencryption-compression.backend';

describe('DEF JSON Web Encryption Compression Backend', () => {
  const backend = new DEFJsonWebEncryptionCompressionBackend();
  const plaintext = Buffer.from('Super secret message.', 'utf8');

  describe('DEF', () => {
    const compressedPlaintext = Buffer.from('Cy4tSC1SKE5NLkotUchNLS5OTE_VAwA', 'base64url');

    describe('compress()', () => {
      it('should compress the provided Plaintext.', async () => {
        await expect(backend.compress(plaintext)).resolves.toStrictEqual(compressedPlaintext);
      });
    });

    describe('decompress()', () => {
      it('should decompress the provided Plaintext.', async () => {
        await expect(backend.decompress(compressedPlaintext)).resolves.toStrictEqual(plaintext);
      });
    });
  });
});
