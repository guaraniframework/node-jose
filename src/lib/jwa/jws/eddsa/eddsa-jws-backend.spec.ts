import { Buffer } from 'buffer';

import { InvalidJwkException } from '../../../exceptions/invalid-jwk.exception';
import { InvalidJwsException } from '../../../exceptions/invalid-jws.exception';
import { OkpPrivateJwk } from '../../jwk/okp/okp-private-jwk';
import { OkpPublicJwk } from '../../jwk/okp/okp-public-jwk';
import { EddsaJwsBackend } from './eddsa-jws-backend';

const message = Buffer.from('Super secret message.');

describe('EdDSA JWS Backend.', () => {
  describe('Ed25519', () => {
    let publicKey!: OkpPublicJwk;
    let privateKey!: OkpPrivateJwk;
    let signature!: Buffer;

    const backend = new EddsaJwsBackend();

    beforeEach(() => {
      publicKey = new OkpPublicJwk({
        kty: 'OKP',
        crv: 'Ed25519',
        x: 'g5p3LK1Mpb1lFnBDRlwvZPZSOnbGFSKnyngC7AOAsgE',
      });

      privateKey = new OkpPrivateJwk({
        ...publicKey.toJSON(),
        d: 'S52ag71xVm7aw2EQA2TWAJGsLKAecKVz2oJJVyK9FPA',
      });
    });

    describe('validateJwk()', () => {
      it('should throw when the provided jwk "crv" is not supported by the ecdsa jws backend.', () => {
        Reflect.set(publicKey, 'crv', 'X25519');

        expect(() => backend['validateJwk'](publicKey)).toThrowWithMessage(
          InvalidJwkException,
          'The jwk parameter "crv" must be one of ["Ed25519", "Ed448"].',
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

  describe('Ed448', () => {
    let publicKey!: OkpPublicJwk;
    let privateKey!: OkpPrivateJwk;
    let signature!: Buffer;

    const backend = new EddsaJwsBackend();

    beforeEach(() => {
      publicKey = new OkpPublicJwk({
        kty: 'OKP',
        crv: 'Ed448',
        x: 'vAF7jwmYardxSMxwGvWOJxphwlfMfsiKfMPFuQLXLACFUHZFnlKEbsnh78QL3yipMt0eqUurfm8A',
      });

      privateKey = new OkpPrivateJwk({
        ...publicKey.toJSON(),
        d: 'E4Haa6qE2nRb4OKOQdLapdEuLVIW7iIi31-oIOzxRsa1lXxz8H0LsgPtdhaZfaiLVdlV2Qt83m22',
      });
    });

    describe('validateJwk()', () => {
      it('should throw when the provided jwk "crv" is not supported by the ecdsa jws backend.', () => {
        Reflect.set(publicKey, 'crv', 'X448');

        expect(() => backend['validateJwk'](publicKey)).toThrowWithMessage(
          InvalidJwkException,
          'The jwk parameter "crv" must be one of ["Ed25519", "Ed448"].',
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
