import { Buffer } from 'buffer';
import { randomBytes } from 'crypto';

import { InvalidJwkException } from '../../../exceptions/invalid-jwk.exception';
import { InvalidJwsException } from '../../../exceptions/invalid-jws.exception';
import { OctJwk } from '../../jwk/oct/oct-jwk';
import { HmacJwsBackend } from './hmac-jws-backend';

const message = Buffer.from('Super secret message.');

const invalidKeySizes: any[] = [
  undefined,
  null,
  true,
  1.2,
  1n,
  'a',
  Symbol('a'),
  Buffer,
  Buffer.alloc(1),
  () => 1,
  {},
  [],
  16,
];

describe('HMAC JWS Backend.', () => {
  describe('constructor', () => {
    it.each(invalidKeySizes)('should throw when providing an unsupported key size.', (keySize) => {
      expect(() => new HmacJwsBackend(keySize)).toThrowWithMessage(
        TypeError,
        `Unsupported key size "${String(keySize)}".`,
      );
    });
  });

  describe('HS256', () => {
    let key!: OctJwk;

    const backend = new HmacJwsBackend(32);

    const signature = Buffer.from('oYyAwnx7D5WIo3L1WWx_zBSNX12nH8lwXQHgpPiApSk', 'base64url');
    const badSignatures = [Buffer.alloc(16, 0), Buffer.alloc(32, 0)];

    beforeEach(() => {
      key = new OctJwk({ kty: 'oct', k: 'qDM80igvja4Tg_tNsEuWDhl2bMM6_NgJEldFhIEuwqQ' });
    });

    describe('validateJwk()', () => {
      it('should throw when providing a small jwk secret.', () => {
        Reflect.set(key, 'k', randomBytes(16).toString('base64url'));

        expect(() => backend['validateJwk'](key)).toThrowWithMessage(
          InvalidJwkException,
          'The jwk parameter "k" must be at least 32 bytes.',
        );
      });
    });

    describe('sign()', () => {
      it('should return the signature of the provided message.', async () => {
        await expect(backend.sign(message, key)).resolves.toEqual(signature);
      });
    });

    describe('verify()', () => {
      it.each(badSignatures)(
        'should throw when the provided signature does not match the calculated signature.',
        async (badSignature) => {
          await expect(backend.verify(badSignature, message, key)).rejects.toThrowWithMessage(
            InvalidJwsException,
            'Signature verification failed.',
          );
        },
      );

      it('should not throw when the provided signature matches the calculated signature.', async () => {
        await expect(backend.verify(signature, message, key)).resolves.not.toThrow();
      });
    });
  });

  describe('HS384', () => {
    let key!: OctJwk;

    const backend = new HmacJwsBackend(48);

    const signature = Buffer.from('coLBQq5PwX6sW1qWC3dFmrSbhEXJhkAvYoZ4C2qngx3bohSdB17_JcmDu5GHRyhD', 'base64url');
    const badSignatures = [Buffer.alloc(24, 0), Buffer.alloc(48, 0)];

    beforeEach(() => {
      key = new OctJwk({ kty: 'oct', k: 'A6zrZGeldxyCH6-7Lshxyc2x19S1athFtq_4in9Wk0o7eRbFTOfSQtXQ5xQYd6dn' });
    });

    describe('validateJwk()', () => {
      it('should throw when providing a small jwk secret.', () => {
        Reflect.set(key, 'k', randomBytes(24).toString('base64url'));

        expect(() => backend['validateJwk'](key)).toThrowWithMessage(
          InvalidJwkException,
          'The jwk parameter "k" must be at least 48 bytes.',
        );
      });
    });

    describe('sign()', () => {
      it('should return the signature of the provided message.', async () => {
        await expect(backend.sign(message, key)).resolves.toEqual(signature);
      });
    });

    describe('verify()', () => {
      it.each(badSignatures)(
        'should throw when the provided signature does not match the calculated signature.',
        async (badSignature) => {
          await expect(backend.verify(badSignature, message, key)).rejects.toThrowWithMessage(
            InvalidJwsException,
            'Signature verification failed.',
          );
        },
      );

      it('should not throw when the provided signature matches the calculated signature.', async () => {
        await expect(backend.verify(signature, message, key)).resolves.not.toThrow();
      });
    });
  });

  describe('HS512', () => {
    let key!: OctJwk;

    const backend = new HmacJwsBackend(64);

    const signature = Buffer.from(
      'pSj6EqzwDIUxL6QX_pBTrElXGvhXoKjAU_637_uEg72sdqnhSwvPkmuVUZARzp6gQe6DFEnXS7SFJkxR6HAL2Q',
      'base64url',
    );

    const badSignatures = [Buffer.alloc(32, 0), Buffer.alloc(64, 0)];

    beforeEach(() => {
      key = new OctJwk({
        kty: 'oct',
        k: 'bWpPugq2lpVgFQ0bFgVmbly3ZWRQf_vTw-K9EmV-S8Q8uRkM8oHgLQI3_k3rYaVBxcNzI2b7TOI3drm8Rdmhlg',
      });
    });

    describe('validateJwk()', () => {
      it('should throw when providing a small jwk secret.', () => {
        Reflect.set(key, 'k', randomBytes(32).toString('base64url'));

        expect(() => backend['validateJwk'](key)).toThrowWithMessage(
          InvalidJwkException,
          'The jwk parameter "k" must be at least 64 bytes.',
        );
      });
    });

    describe('sign()', () => {
      it('should return the signature of the provided message.', async () => {
        await expect(backend.sign(message, key)).resolves.toEqual(signature);
      });
    });

    describe('verify()', () => {
      it.each(badSignatures)(
        'should throw when the provided signature does not match the calculated signature.',
        async (badSignature) => {
          await expect(backend.verify(badSignature, message, key)).rejects.toThrowWithMessage(
            InvalidJwsException,
            'Signature verification failed.',
          );
        },
      );

      it('should not throw when the provided signature matches the calculated signature.', async () => {
        await expect(backend.verify(signature, message, key)).resolves.not.toThrow();
      });
    });
  });
});
