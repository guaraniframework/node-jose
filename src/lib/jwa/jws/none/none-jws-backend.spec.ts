import { Buffer } from 'buffer';

import { InvalidJwsException } from '../../../exceptions/invalid-jws.exception';
import { NoneJwsBackend } from './none-jws-backend';

const message = Buffer.from('Super secret message.');

describe('none JWS Backend', () => {
  const backend = new NoneJwsBackend();

  describe('sign()', () => {
    it('should return an empty buffer.', async () => {
      await expect(backend.sign(message, null)).resolves.toEqual(Buffer.alloc(0));
    });
  });

  describe('verify()', () => {
    it('should throw when the signature is not an empty buffer.', async () => {
      await expect(backend.verify(message, message, null)).rejects.toThrowWithMessage(
        InvalidJwsException,
        'The jws algorithm "none" must be used with an empty signature.',
      );
    });

    it('should not throw when verifying an empty signature buffer.', async () => {
      await expect(backend.verify(Buffer.alloc(0), message, null)).resolves.not.toThrow();
    });
  });
});
