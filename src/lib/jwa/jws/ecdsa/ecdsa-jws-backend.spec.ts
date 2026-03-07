import { Buffer } from 'buffer';

import { InvalidJwkException } from '../../../exceptions/invalid-jwk.exception';
import { InvalidJwsException } from '../../../exceptions/invalid-jws.exception';
import { EcPrivateJwk } from '../../jwk/ec/ec-private-jwk';
import { EcPublicJwk } from '../../jwk/ec/ec-public-jwk';
import { EcdsaJwsBackend } from './ecdsa-jws-backend';

const message = Buffer.from('Super secret message.');

const invalidCurves: any[] = [
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
  'a',
];

describe('ECDSA JWS Backend.', () => {
  describe('constructor', () => {
    it.each(invalidCurves)('should throw when providing an unsupported elliptic curve.', (curve) => {
      expect(() => new EcdsaJwsBackend(curve)).toThrowWithMessage(
        TypeError,
        `Unsupported elliptic curve "${String(curve)}".`,
      );
    });
  });

  describe('ES256', () => {
    let publicKey!: EcPublicJwk;
    let privateKey!: EcPrivateJwk;
    let signature!: Buffer;

    const backend = new EcdsaJwsBackend('P-256');

    beforeEach(() => {
      publicKey = new EcPublicJwk({
        kty: 'EC',
        crv: 'P-256',
        x: 'n8MBkJ0EfDC91TF_B2j1yLOEJ8JS2w-vBc5MsjNiIHg',
        y: 'NbGNGGRtO5YuiLrYvbS-vajMPAuqT-sfmpmNcCNxElg',
      });

      privateKey = new EcPrivateJwk({
        ...publicKey.toJSON(),
        d: 'YyUqj9enPBrlUtK1rf9ycAU9OUUYNlh7Fir0x8hlWX0',
      });
    });

    describe('validateJwk()', () => {
      it('should throw when the provided jwk "crv" is not supported by the ecdsa jws backend.', () => {
        Reflect.set(publicKey, 'crv', 'P-384');

        expect(() => backend['validateJwk'](publicKey)).toThrowWithMessage(
          InvalidJwkException,
          'The jwk parameter "crv" must be "P-256".',
        );
      });
    });

    describe('sign()', () => {
      it('should return the signature of the provided message.', async () => {
        signature = await backend.sign(message, privateKey);
        expect(signature).toBeInstanceOf(Buffer);
      });
    });

    describe('verify()', () => {
      it('should throw when the provided signature does not match the calculated signature.', async () => {
        await expect(backend.verify(Buffer.alloc(0), message, publicKey)).rejects.toThrowWithMessage(
          InvalidJwsException,
          'Signature verification failed.',
        );
      });

      it('should not throw when the provided signature matches the calculated signature.', async () => {
        await expect(backend.verify(signature, message, publicKey)).resolves.not.toThrow();
      });
    });
  });

  describe('ES384', () => {
    let publicKey!: EcPublicJwk;
    let privateKey!: EcPrivateJwk;
    let signature!: Buffer;

    const backend = new EcdsaJwsBackend('P-384');

    beforeEach(() => {
      publicKey = new EcPublicJwk({
        kty: 'EC',
        crv: 'P-384',
        x: 'WQHUcjVyE63vMl-SJNYYmqgYkJKkNGOctFcD368nyI2DogjP-34teV5KUZo82AxT',
        y: 'T4hHQx5WkQxjInUkQ1mMBu9iOw_ICOC5wh8QP79BRi-UPYfMP0z7b-LODdijwwFb',
      });

      privateKey = new EcPrivateJwk({
        ...publicKey.toJSON(),
        d: 'Sp2paYMyI8y4oWP7GfQXaSyaoFjyd-9IvqnQlAWAdYg_z-45Q809-_kgR47c15X2',
      });
    });

    describe('validateJwk()', () => {
      it('should throw when the provided jwk "crv" is not supported by the ecdsa jws backend.', () => {
        Reflect.set(publicKey, 'crv', 'P-521');

        expect(() => backend['validateJwk'](publicKey)).toThrowWithMessage(
          InvalidJwkException,
          'The jwk parameter "crv" must be "P-384".',
        );
      });
    });

    describe('sign()', () => {
      it('should return the signature of the provided message.', async () => {
        signature = await backend.sign(message, privateKey);
        expect(signature).toBeInstanceOf(Buffer);
      });
    });

    describe('verify()', () => {
      it('should throw when the provided signature does not match the calculated signature.', async () => {
        await expect(backend.verify(Buffer.alloc(0), message, publicKey)).rejects.toThrowWithMessage(
          InvalidJwsException,
          'Signature verification failed.',
        );
      });

      it('should not throw when the provided signature matches the calculated signature.', async () => {
        await expect(backend.verify(signature, message, publicKey)).resolves.not.toThrow();
      });
    });
  });

  describe('ES512', () => {
    let publicKey!: EcPublicJwk;
    let privateKey!: EcPrivateJwk;
    let signature!: Buffer;

    const backend = new EcdsaJwsBackend('P-521');

    beforeEach(() => {
      publicKey = new EcPublicJwk({
        kty: 'EC',
        crv: 'P-521',
        x: 'AcQkwaU8dBVZygHPgR7uukQGwy1SHMbM3bkXWnC3gDm6I_OW5RQgadCWSbZ1e2wV4fZWw1YaspSU8qwmZ1_jKDNt',
        y: 'ADU7z6Rqkp2EJRzcNPw_-EmKyLS79zNoGyFVFNR0WTjmUopRk6xEZz6wW_ELgllOuTEuAkneRupjGNgObgpJJxNN',
      });

      privateKey = new EcPrivateJwk({
        ...publicKey.toJSON(),
        d: 'AdTlQfG5YXpKKdb8ryx4k4Wn-MQN8KgPdfMkOFEs56c5phlEXPnu7nsOszCzkWQ5V9cL7GvDo5KSgDg0P8eYhfv4',
      });
    });

    describe('validateJwk()', () => {
      it('should throw when the provided jwk "crv" is not supported by the ecdsa jws backend.', () => {
        Reflect.set(publicKey, 'crv', 'P-256');

        expect(() => backend['validateJwk'](publicKey)).toThrowWithMessage(
          InvalidJwkException,
          'The jwk parameter "crv" must be "P-521".',
        );
      });
    });

    describe('sign()', () => {
      it('should return the signature of the provided message.', async () => {
        signature = await backend.sign(message, privateKey);
        expect(signature).toBeInstanceOf(Buffer);
      });
    });

    describe('verify()', () => {
      it('should throw when the provided signature does not match the calculated signature.', async () => {
        await expect(backend.verify(Buffer.alloc(0), message, publicKey)).rejects.toThrowWithMessage(
          InvalidJwsException,
          'Signature verification failed.',
        );
      });

      it('should not throw when the provided signature matches the calculated signature.', async () => {
        await expect(backend.verify(signature, message, publicKey)).resolves.not.toThrow();
      });
    });
  });
});
