import { Buffer } from 'buffer';

import { InvalidJsonWebKeyError } from '../../../errors/invalid-jsonwebkey.error';
import { InvalidJsonWebSignatureError } from '../../../errors/invalid-jsonwebsignature.error';
import { EllipticCurveJsonWebKey } from '../../jwk/ec/elliptic-curve.jsonwebkey';
import { OctetKeyPairJsonWebKey } from '../../jwk/okp/octet-key-pair.jsonwebkey';
import { ECDSAJsonWebSignatureDigitalSignatureBackend } from './ecdsa-jsonwebsignature-digital-signature.backend';

const invalidJsonWebKeys: any[] = [
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
];

describe('ECDSA JSON Web Signature Digital Signature Backend.', () => {
  const message = Buffer.from('Super secret message.', 'utf8');

  const wrongAlgJsonWebKey = new EllipticCurveJsonWebKey({
    kty: 'EC',
    crv: 'P-256',
    x: '4c_cS6IT6jaVQeobt_6BDCTmzBaBOTmmiSCpjd5a6Og',
    y: 'mnrPnCFTDkGdEwilabaqM7DzwlAFgetZTmP9ycHPxF8',
    alg: 'ECDH-ES',
  });

  const wrongKtyJsonWebKey = new OctetKeyPairJsonWebKey({
    kty: 'OKP',
    crv: 'Ed25519',
    x: 'aNoALKSUE1UsotuZvHUj1HEGqhpzLtsSTLmkBITDMAk',
    d: 'tccuS3jrlRwPaNsn2YxpUuMCqvnlsIgy_T0S7qVmo-A',
  });

  const wrongSignature = Buffer.from('APwj7CgHdXxQsdUFm-JpLib8ufFZMWM0JeG7OboIhKc', 'base64url');
  const wrongMessage = Buffer.from('Bad message.', 'utf8');

  describe('ES256', () => {
    const backend = new ECDSAJsonWebSignatureDigitalSignatureBackend('ES256');

    const publicJsonWebKey = new EllipticCurveJsonWebKey({
      kty: 'EC',
      crv: 'P-256',
      x: '4c_cS6IT6jaVQeobt_6BDCTmzBaBOTmmiSCpjd5a6Og',
      y: 'mnrPnCFTDkGdEwilabaqM7DzwlAFgetZTmP9ycHPxF8',
    });

    const privateJsonWebKey = new EllipticCurveJsonWebKey({
      ...publicJsonWebKey.parameters,
      d: 'bwVX6Vx-TOfGKYOPAcu2xhaj3JUzs-McsC-suaHnFBo',
    });

    let signature!: Buffer;

    const wrongCrvJsonWebKey = new EllipticCurveJsonWebKey({
      kty: 'EC',
      crv: 'secp256k1',
      x: 'cVoZG6ar2ubapq6oQY4PmfQBJxA0KSpdD9a9Zrh7LDs',
      y: 'X4-9Mjy0NMjTQTdZFuG3xYd52ClKShWrKTaJkXxgdN4',
      d: 'nwW3RLFW8c3kxI8d6SrH6mB6UwlqcyOr5HZL-oprBTk',
    });

    const wrongJsonWebKey = new EllipticCurveJsonWebKey({
      kty: 'EC',
      crv: 'P-256',
      x: 'P8dDVG6zFfWf7vw7piJI9SIZuQVwnG4HLhs6FHHab-Y',
      y: 'YR7lER3XShyUV9ORdSBrPYyDz83YluVuPGcMc_nimhE',
    });

    describe('sign()', () => {
      it.each(invalidJsonWebKeys)(
        'should throw when the provided JSON Web Key cannot be used by the JSON Web Signature Algorithm.',
        async (jsonWebKey) => {
          await expect(backend.sign(message, jsonWebKey)).rejects.toThrowWithMessage(
            InvalidJsonWebKeyError,
            'The provided JSON Web Key cannot be used by the JSON Web Signature Algorithm.',
          );
        },
      );

      it('should throw when the provided JSON Web Key Parameter "alg" does not match the JSON Web Signature Algorithm.', async () => {
        await expect(backend.sign(message, wrongAlgJsonWebKey)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The provided JSON Web Key cannot be used by the JSON Web Signature Algorithm.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "kty" does not match the required JSON Web Key Key Type.', async () => {
        await expect(backend.sign(message, <any>wrongKtyJsonWebKey)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Signature Algorithm only accepts "EC" JSON Web Keys.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "crv" does not match the required JSON Web Key Elliptic Curve.', async () => {
        await expect(backend.sign(message, wrongCrvJsonWebKey)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Key Parameter "crv" must be "P-256".',
        );
      });

      it('should throw when the provided JSON Web Key is not a Private Key.', async () => {
        await expect(backend.sign(message, publicJsonWebKey)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The provided JSON Web Key cannot be used to sign a Message.',
        );
      });

      it('should sign the provided Message.', async () => {
        await expect(async () => (signature = await backend.sign(message, privateJsonWebKey))).resolves.not.toThrow();

        expect(signature).toBeInstanceOf(Buffer);
        expect(signature).not.toBeEmpty();
      });
    });

    describe('verify()', () => {
      it.each(invalidJsonWebKeys)(
        'should throw when the provided JSON Web Key cannot be used by the JSON Web Signature Algorithm.',
        async (jsonWebKey) => {
          await expect(backend.verify(signature, message, jsonWebKey)).rejects.toThrowWithMessage(
            InvalidJsonWebKeyError,
            'The provided JSON Web Key cannot be used by the JSON Web Signature Algorithm.',
          );
        },
      );

      it('should throw when the provided JSON Web Key Parameter "alg" does not match the JSON Web Signature Algorithm.', async () => {
        await expect(backend.verify(signature, message, wrongAlgJsonWebKey)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The provided JSON Web Key cannot be used by the JSON Web Signature Algorithm.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "kty" does not match the required JSON Web Key Key Type.', async () => {
        await expect(backend.verify(signature, message, <any>wrongKtyJsonWebKey)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Signature Algorithm only accepts "EC" JSON Web Keys.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "crv" does not match the required JSON Web Key Elliptic Curve.', async () => {
        await expect(backend.verify(signature, message, wrongCrvJsonWebKey)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Key Parameter "crv" must be "P-256".',
        );
      });

      it('should throw when the provided Signature is invalid.', async () => {
        await expect(backend.verify(wrongSignature, message, publicJsonWebKey)).rejects.toThrowWithMessage(
          InvalidJsonWebSignatureError,
          'The provided JSON Web Signature is invalid.',
        );
      });

      it('should throw when the provided Message is invalid.', async () => {
        await expect(backend.verify(signature, wrongMessage, publicJsonWebKey)).rejects.toThrowWithMessage(
          InvalidJsonWebSignatureError,
          'The provided JSON Web Signature is invalid.',
        );
      });

      it('should throw when the provided JSON Web Key is invalid.', async () => {
        await expect(backend.verify(signature, message, wrongJsonWebKey)).rejects.toThrowWithMessage(
          InvalidJsonWebSignatureError,
          'The provided JSON Web Signature is invalid.',
        );
      });

      it('should not throw when the provided Signature matches the provided Message.', async () => {
        await expect(backend.verify(signature, message, publicJsonWebKey)).resolves.not.toThrow();
      });
    });
  });

  describe('ES256K', () => {
    const backend = new ECDSAJsonWebSignatureDigitalSignatureBackend('ES256K');

    const publicJsonWebKey = new EllipticCurveJsonWebKey({
      kty: 'EC',
      crv: 'secp256k1',
      x: 'cVoZG6ar2ubapq6oQY4PmfQBJxA0KSpdD9a9Zrh7LDs',
      y: 'X4-9Mjy0NMjTQTdZFuG3xYd52ClKShWrKTaJkXxgdN4',
    });

    const privateJsonWebKey = new EllipticCurveJsonWebKey({
      ...publicJsonWebKey.parameters,
      d: 'nwW3RLFW8c3kxI8d6SrH6mB6UwlqcyOr5HZL-oprBTk',
    });

    let signature!: Buffer;

    const wrongCrvJsonWebKey = new EllipticCurveJsonWebKey({
      kty: 'EC',
      crv: 'P-384',
      x: 'WQHUcjVyE63vMl-SJNYYmqgYkJKkNGOctFcD368nyI2DogjP-34teV5KUZo82AxT',
      y: 'T4hHQx5WkQxjInUkQ1mMBu9iOw_ICOC5wh8QP79BRi-UPYfMP0z7b-LODdijwwFb',
      d: 'Sp2paYMyI8y4oWP7GfQXaSyaoFjyd-9IvqnQlAWAdYg_z-45Q809-_kgR47c15X2',
    });

    const wrongJsonWebKey = new EllipticCurveJsonWebKey({
      kty: 'EC',
      crv: 'secp256k1',
      x: '9u4Dfjc7_AXK6mbOEHwAaGgRufMXNjrq5ErcKZAEyAg',
      y: 'W9v1MWHTQTBzIeDQ-BLEQOK92-EWcUf5lAdv_bHQOMA',
    });

    describe('sign()', () => {
      it.each(invalidJsonWebKeys)(
        'should throw when the provided JSON Web Key cannot be used by the JSON Web Signature Algorithm.',
        async (jsonWebKey) => {
          await expect(backend.sign(message, jsonWebKey)).rejects.toThrowWithMessage(
            InvalidJsonWebKeyError,
            'The provided JSON Web Key cannot be used by the JSON Web Signature Algorithm.',
          );
        },
      );

      it('should throw when the provided JSON Web Key Parameter "alg" does not match the JSON Web Signature Algorithm.', async () => {
        await expect(backend.sign(message, wrongAlgJsonWebKey)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The provided JSON Web Key cannot be used by the JSON Web Signature Algorithm.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "kty" does not match the required JSON Web Key Key Type.', async () => {
        await expect(backend.sign(message, <any>wrongKtyJsonWebKey)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Signature Algorithm only accepts "EC" JSON Web Keys.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "crv" does not match the required JSON Web Key Elliptic Curve.', async () => {
        await expect(backend.sign(message, wrongCrvJsonWebKey)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Key Parameter "crv" must be "secp256k1".',
        );
      });

      it('should throw when the provided JSON Web Key is not a Private Key.', async () => {
        await expect(backend.sign(message, publicJsonWebKey)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The provided JSON Web Key cannot be used to sign a Message.',
        );
      });

      it('should sign the provided Message.', async () => {
        await expect(async () => (signature = await backend.sign(message, privateJsonWebKey))).resolves.not.toThrow();

        expect(signature).toBeInstanceOf(Buffer);
        expect(signature).not.toBeEmpty();
      });
    });

    describe('verify()', () => {
      it.each(invalidJsonWebKeys)(
        'should throw when the provided JSON Web Key cannot be used by the JSON Web Signature Algorithm.',
        async (jsonWebKey) => {
          await expect(backend.verify(signature, message, jsonWebKey)).rejects.toThrowWithMessage(
            InvalidJsonWebKeyError,
            'The provided JSON Web Key cannot be used by the JSON Web Signature Algorithm.',
          );
        },
      );

      it('should throw when the provided JSON Web Key Parameter "alg" does not match the JSON Web Signature Algorithm.', async () => {
        await expect(backend.verify(signature, message, wrongAlgJsonWebKey)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The provided JSON Web Key cannot be used by the JSON Web Signature Algorithm.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "kty" does not match the required JSON Web Key Key Type.', async () => {
        await expect(backend.verify(signature, message, <any>wrongKtyJsonWebKey)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Signature Algorithm only accepts "EC" JSON Web Keys.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "crv" does not match the required JSON Web Key Elliptic Curve.', async () => {
        await expect(backend.verify(signature, message, wrongCrvJsonWebKey)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Key Parameter "crv" must be "secp256k1".',
        );
      });

      it('should throw when the provided Signature is invalid.', async () => {
        await expect(backend.verify(wrongSignature, message, publicJsonWebKey)).rejects.toThrowWithMessage(
          InvalidJsonWebSignatureError,
          'The provided JSON Web Signature is invalid.',
        );
      });

      it('should throw when the provided Message is invalid.', async () => {
        await expect(backend.verify(signature, wrongMessage, publicJsonWebKey)).rejects.toThrowWithMessage(
          InvalidJsonWebSignatureError,
          'The provided JSON Web Signature is invalid.',
        );
      });

      it('should throw when the provided JSON Web Key is invalid.', async () => {
        await expect(backend.verify(signature, message, wrongJsonWebKey)).rejects.toThrowWithMessage(
          InvalidJsonWebSignatureError,
          'The provided JSON Web Signature is invalid.',
        );
      });

      it('should not throw when the provided Signature matches the provided Message.', async () => {
        await expect(backend.verify(signature, message, publicJsonWebKey)).resolves.not.toThrow();
      });
    });
  });

  describe('ES384', () => {
    const backend = new ECDSAJsonWebSignatureDigitalSignatureBackend('ES384');

    const publicJsonWebKey = new EllipticCurveJsonWebKey({
      kty: 'EC',
      crv: 'P-384',
      x: 'WQHUcjVyE63vMl-SJNYYmqgYkJKkNGOctFcD368nyI2DogjP-34teV5KUZo82AxT',
      y: 'T4hHQx5WkQxjInUkQ1mMBu9iOw_ICOC5wh8QP79BRi-UPYfMP0z7b-LODdijwwFb',
    });

    const privateJsonWebKey = new EllipticCurveJsonWebKey({
      ...publicJsonWebKey.parameters,
      d: 'Sp2paYMyI8y4oWP7GfQXaSyaoFjyd-9IvqnQlAWAdYg_z-45Q809-_kgR47c15X2',
    });

    let signature!: Buffer;

    const wrongCrvJsonWebKey = new EllipticCurveJsonWebKey({
      kty: 'EC',
      crv: 'P-521',
      x: 'AcQkwaU8dBVZygHPgR7uukQGwy1SHMbM3bkXWnC3gDm6I_OW5RQgadCWSbZ1e2wV4fZWw1YaspSU8qwmZ1_jKDNt',
      y: 'ADU7z6Rqkp2EJRzcNPw_-EmKyLS79zNoGyFVFNR0WTjmUopRk6xEZz6wW_ELgllOuTEuAkneRupjGNgObgpJJxNN',
      d: 'AdTlQfG5YXpKKdb8ryx4k4Wn-MQN8KgPdfMkOFEs56c5phlEXPnu7nsOszCzkWQ5V9cL7GvDo5KSgDg0P8eYhfv4',
    });

    const wrongJsonWebKey = new EllipticCurveJsonWebKey({
      kty: 'EC',
      crv: 'P-384',
      x: 'ZFxBkTpoI0DvV_kEr44wLvepCFj7xQBPOwHk-UjxY8MQUsqq-vImHKJ5hZwj5wNx',
      y: 'O48vaT-Wt1bRU1kR7mDAV59RVn5mDbp901Zu3qJr6OTgAbi-TuvPwa4Bg3e2d4Fv',
    });

    describe('sign()', () => {
      it.each(invalidJsonWebKeys)(
        'should throw when the provided JSON Web Key cannot be used by the JSON Web Signature Algorithm.',
        async (jsonWebKey) => {
          await expect(backend.sign(message, jsonWebKey)).rejects.toThrowWithMessage(
            InvalidJsonWebKeyError,
            'The provided JSON Web Key cannot be used by the JSON Web Signature Algorithm.',
          );
        },
      );

      it('should throw when the provided JSON Web Key Parameter "alg" does not match the JSON Web Signature Algorithm.', async () => {
        await expect(backend.sign(message, wrongAlgJsonWebKey)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The provided JSON Web Key cannot be used by the JSON Web Signature Algorithm.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "kty" does not match the required JSON Web Key Key Type.', async () => {
        await expect(backend.sign(message, <any>wrongKtyJsonWebKey)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Signature Algorithm only accepts "EC" JSON Web Keys.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "crv" does not match the required JSON Web Key Elliptic Curve.', async () => {
        await expect(backend.sign(message, wrongCrvJsonWebKey)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Key Parameter "crv" must be "P-384".',
        );
      });

      it('should throw when the provided JSON Web Key is not a Private Key.', async () => {
        await expect(backend.sign(message, publicJsonWebKey)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The provided JSON Web Key cannot be used to sign a Message.',
        );
      });

      it('should sign the provided Message.', async () => {
        await expect(async () => (signature = await backend.sign(message, privateJsonWebKey))).resolves.not.toThrow();

        expect(signature).toBeInstanceOf(Buffer);
        expect(signature).not.toBeEmpty();
      });
    });

    describe('verify()', () => {
      it.each(invalidJsonWebKeys)(
        'should throw when the provided JSON Web Key cannot be used by the JSON Web Signature Algorithm.',
        async (jsonWebKey) => {
          await expect(backend.verify(signature, message, jsonWebKey)).rejects.toThrowWithMessage(
            InvalidJsonWebKeyError,
            'The provided JSON Web Key cannot be used by the JSON Web Signature Algorithm.',
          );
        },
      );

      it('should throw when the provided JSON Web Key Parameter "alg" does not match the JSON Web Signature Algorithm.', async () => {
        await expect(backend.verify(signature, message, wrongAlgJsonWebKey)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The provided JSON Web Key cannot be used by the JSON Web Signature Algorithm.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "kty" does not match the required JSON Web Key Key Type.', async () => {
        await expect(backend.verify(signature, message, <any>wrongKtyJsonWebKey)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Signature Algorithm only accepts "EC" JSON Web Keys.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "crv" does not match the required JSON Web Key Elliptic Curve.', async () => {
        await expect(backend.verify(signature, message, wrongCrvJsonWebKey)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Key Parameter "crv" must be "P-384".',
        );
      });

      it('should throw when the provided Signature is invalid.', async () => {
        await expect(backend.verify(wrongSignature, message, publicJsonWebKey)).rejects.toThrowWithMessage(
          InvalidJsonWebSignatureError,
          'The provided JSON Web Signature is invalid.',
        );
      });

      it('should throw when the provided Message is invalid.', async () => {
        await expect(backend.verify(signature, wrongMessage, publicJsonWebKey)).rejects.toThrowWithMessage(
          InvalidJsonWebSignatureError,
          'The provided JSON Web Signature is invalid.',
        );
      });

      it('should throw when the provided JSON Web Key is invalid.', async () => {
        await expect(backend.verify(signature, message, wrongJsonWebKey)).rejects.toThrowWithMessage(
          InvalidJsonWebSignatureError,
          'The provided JSON Web Signature is invalid.',
        );
      });

      it('should not throw when the provided Signature matches the provided Message.', async () => {
        await expect(backend.verify(signature, message, publicJsonWebKey)).resolves.not.toThrow();
      });
    });
  });

  describe('ES512', () => {
    const backend = new ECDSAJsonWebSignatureDigitalSignatureBackend('ES512');

    const publicJsonWebKey = new EllipticCurveJsonWebKey({
      kty: 'EC',
      crv: 'P-521',
      x: 'AcQkwaU8dBVZygHPgR7uukQGwy1SHMbM3bkXWnC3gDm6I_OW5RQgadCWSbZ1e2wV4fZWw1YaspSU8qwmZ1_jKDNt',
      y: 'ADU7z6Rqkp2EJRzcNPw_-EmKyLS79zNoGyFVFNR0WTjmUopRk6xEZz6wW_ELgllOuTEuAkneRupjGNgObgpJJxNN',
    });

    const privateJsonWebKey = new EllipticCurveJsonWebKey({
      ...publicJsonWebKey.parameters,
      d: 'AdTlQfG5YXpKKdb8ryx4k4Wn-MQN8KgPdfMkOFEs56c5phlEXPnu7nsOszCzkWQ5V9cL7GvDo5KSgDg0P8eYhfv4',
    });

    let signature!: Buffer;

    const wrongCrvJsonWebKey = new EllipticCurveJsonWebKey({
      kty: 'EC',
      crv: 'P-256',
      x: '4c_cS6IT6jaVQeobt_6BDCTmzBaBOTmmiSCpjd5a6Og',
      y: 'mnrPnCFTDkGdEwilabaqM7DzwlAFgetZTmP9ycHPxF8',
      d: 'bwVX6Vx-TOfGKYOPAcu2xhaj3JUzs-McsC-suaHnFBo',
    });

    const wrongJsonWebKey = new EllipticCurveJsonWebKey({
      kty: 'EC',
      crv: 'P-521',
      x: 'Abrl89-OjKQ3JaTXeDQdfhho-y3pdS-lYy0M26kVp6mUDkNJHhN_sjLfUnWngXwJc7Wpin5OnQ2Q9SdEcCZ-YwH0',
      y: 'AaQyradiKRKjW3AQXaiKkneqkEE-TUg1iPl3qbrXQPcINAniE5m3kU16w-27Xn-_0oksqx6AgltGdlrr0M3RuEu1',
    });

    describe('sign()', () => {
      it.each(invalidJsonWebKeys)(
        'should throw when the provided JSON Web Key cannot be used by the JSON Web Signature Algorithm.',
        async (jsonWebKey) => {
          await expect(backend.sign(message, jsonWebKey)).rejects.toThrowWithMessage(
            InvalidJsonWebKeyError,
            'The provided JSON Web Key cannot be used by the JSON Web Signature Algorithm.',
          );
        },
      );

      it('should throw when the provided JSON Web Key Parameter "alg" does not match the JSON Web Signature Algorithm.', async () => {
        await expect(backend.sign(message, wrongAlgJsonWebKey)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The provided JSON Web Key cannot be used by the JSON Web Signature Algorithm.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "kty" does not match the required JSON Web Key Key Type.', async () => {
        await expect(backend.sign(message, <any>wrongKtyJsonWebKey)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Signature Algorithm only accepts "EC" JSON Web Keys.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "crv" does not match the required JSON Web Key Elliptic Curve.', async () => {
        await expect(backend.sign(message, wrongCrvJsonWebKey)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Key Parameter "crv" must be "P-521".',
        );
      });

      it('should throw when the provided JSON Web Key is not a Private Key.', async () => {
        await expect(backend.sign(message, publicJsonWebKey)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The provided JSON Web Key cannot be used to sign a Message.',
        );
      });

      it('should sign the provided Message.', async () => {
        await expect(async () => (signature = await backend.sign(message, privateJsonWebKey))).resolves.not.toThrow();

        expect(signature).toBeInstanceOf(Buffer);
        expect(signature).not.toBeEmpty();
      });
    });

    describe('verify()', () => {
      it.each(invalidJsonWebKeys)(
        'should throw when the provided JSON Web Key cannot be used by the JSON Web Signature Algorithm.',
        async (jsonWebKey) => {
          await expect(backend.verify(signature, message, jsonWebKey)).rejects.toThrowWithMessage(
            InvalidJsonWebKeyError,
            'The provided JSON Web Key cannot be used by the JSON Web Signature Algorithm.',
          );
        },
      );

      it('should throw when the provided JSON Web Key Parameter "alg" does not match the JSON Web Signature Algorithm.', async () => {
        await expect(backend.verify(signature, message, wrongAlgJsonWebKey)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The provided JSON Web Key cannot be used by the JSON Web Signature Algorithm.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "kty" does not match the required JSON Web Key Key Type.', async () => {
        await expect(backend.verify(signature, message, <any>wrongKtyJsonWebKey)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Signature Algorithm only accepts "EC" JSON Web Keys.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "crv" does not match the required JSON Web Key Elliptic Curve.', async () => {
        await expect(backend.verify(signature, message, wrongCrvJsonWebKey)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Key Parameter "crv" must be "P-521".',
        );
      });

      it('should throw when the provided Signature is invalid.', async () => {
        await expect(backend.verify(wrongSignature, message, publicJsonWebKey)).rejects.toThrowWithMessage(
          InvalidJsonWebSignatureError,
          'The provided JSON Web Signature is invalid.',
        );
      });

      it('should throw when the provided Message is invalid.', async () => {
        await expect(backend.verify(signature, wrongMessage, publicJsonWebKey)).rejects.toThrowWithMessage(
          InvalidJsonWebSignatureError,
          'The provided JSON Web Signature is invalid.',
        );
      });

      it('should throw when the provided JSON Web Key is invalid.', async () => {
        await expect(backend.verify(signature, message, wrongJsonWebKey)).rejects.toThrowWithMessage(
          InvalidJsonWebSignatureError,
          'The provided JSON Web Signature is invalid.',
        );
      });

      it('should not throw when the provided Signature matches the provided Message.', async () => {
        await expect(backend.verify(signature, message, publicJsonWebKey)).resolves.not.toThrow();
      });
    });
  });
});
