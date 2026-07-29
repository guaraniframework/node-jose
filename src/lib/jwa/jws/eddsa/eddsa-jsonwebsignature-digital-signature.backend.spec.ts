import { Buffer } from 'buffer';

import { InvalidJsonWebKeyError } from '../../../errors/invalid-jsonwebkey.error';
import { InvalidJsonWebSignatureError } from '../../../errors/invalid-jsonwebsignature.error';
import { OctetSequenceJsonWebKey } from '../../jwk/oct/octet-sequence.jsonwebkey';
import { OctetKeyPairJsonWebKey } from '../../jwk/okp/octet-key-pair.jsonwebkey';
import { EdDSAJsonWebSignatureDigitalSignatureBackend } from './eddsa-jsonwebsignature-digital-signature.backend';

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

describe('EdDSA JSON Web Signature Digital Signature Backend.', () => {
  const backend = new EdDSAJsonWebSignatureDigitalSignatureBackend();

  const message = Buffer.from('Super secret message.', 'utf8');

  const wrongAlgJwk = new OctetKeyPairJsonWebKey({
    kty: 'OKP',
    crv: 'Ed25519',
    x: 'g5p3LK1Mpb1lFnBDRlwvZPZSOnbGFSKnyngC7AOAsgE',
    alg: 'ECDH-ES',
  });

  const wrongKtyJwk = new OctetSequenceJsonWebKey({
    kty: 'oct',
    k: 'qDM80igvja4Tg_tNsEuWDhl2bMM6_NgJEldFhIEuwqQ',
  });

  const wrongSignature = Buffer.from('APwj7CgHdXxQsdUFm-JpLib8ufFZMWM0JeG7OboIhKc', 'base64url');
  const wrongMessage = Buffer.from('Bad message.', 'utf8');

  describe('EdDSA Ed25519', () => {
    const publicJwk = new OctetKeyPairJsonWebKey({
      kty: 'OKP',
      crv: 'Ed25519',
      x: 'g5p3LK1Mpb1lFnBDRlwvZPZSOnbGFSKnyngC7AOAsgE',
    });

    const privateJwk = new OctetKeyPairJsonWebKey({
      ...publicJwk.parameters,
      d: 'S52ag71xVm7aw2EQA2TWAJGsLKAecKVz2oJJVyK9FPA',
    });

    let signature!: Buffer;

    const wrongCrvJwk = new OctetKeyPairJsonWebKey({
      kty: 'OKP',
      crv: 'X25519',
      x: 'piAPLSP7omNMDiCWrKJPdM5PRfsWsBTTGKHtmvsAbBs',
      d: 'mCSw7z-uai0ZuVVFqsYcjGUwZMwVp0M8-hLYa-SAokQ',
    });

    const wrongJwk = new OctetKeyPairJsonWebKey({
      kty: 'OKP',
      crv: 'Ed25519',
      x: '40e57bj7bcIG4kdv4_uiN0xMufUEJbmNU1GdRtb0JVI',
    });

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

      it('should throw when the provided JSON Web Key Parameter "alg" does not match the JSON Web Signature Algorithm.', async () => {
        await expect(backend.sign(message, wrongAlgJwk)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The provided JSON Web Key cannot be used by the JSON Web Signature Algorithm.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "kty" does not match the required JSON Web Key Key Type.', async () => {
        await expect(backend.sign(message, <any>wrongKtyJwk)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Signature Algorithm only accepts "OKP" JSON Web Keys.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "crv" does not match the required JSON Web Key Edwards Curve.', async () => {
        await expect(backend.sign(message, wrongCrvJwk)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Key Parameters "crv" must be "Ed25519" or "Ed448".',
        );
      });

      it('should throw when the provided JSON Web Key is not a Private Key.', async () => {
        await expect(backend.sign(message, publicJwk)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The provided JSON Web Key cannot be used to sign a Message.',
        );
      });

      it('should sign the provided Message.', async () => {
        await expect(async () => (signature = await backend.sign(message, privateJwk))).resolves.not.toThrow();

        expect(signature).toBeInstanceOf(Buffer);
        expect(signature).not.toBeEmpty();
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

      it('should throw when the provided JSON Web Key Parameter "alg" does not match the JSON Web Signature Algorithm.', async () => {
        await expect(backend.verify(signature, message, wrongAlgJwk)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The provided JSON Web Key cannot be used by the JSON Web Signature Algorithm.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "kty" does not match the required JSON Web Key Key Type.', async () => {
        await expect(backend.verify(signature, message, <any>wrongKtyJwk)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Signature Algorithm only accepts "OKP" JSON Web Keys.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "crv" does not match the required JSON Web Key Edwards Curve.', async () => {
        await expect(backend.verify(signature, message, wrongCrvJwk)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Key Parameters "crv" must be "Ed25519" or "Ed448".',
        );
      });

      it('should throw when the provided Signature is invalid.', async () => {
        await expect(backend.verify(wrongSignature, message, publicJwk)).rejects.toThrowWithMessage(
          InvalidJsonWebSignatureError,
          'The provided JSON Web Signature is invalid.',
        );
      });

      it('should throw when the provided Message is invalid.', async () => {
        await expect(backend.verify(signature, wrongMessage, publicJwk)).rejects.toThrowWithMessage(
          InvalidJsonWebSignatureError,
          'The provided JSON Web Signature is invalid.',
        );
      });

      it('should throw when the provided JSON Web Key is invalid.', async () => {
        await expect(backend.verify(signature, message, wrongJwk)).rejects.toThrowWithMessage(
          InvalidJsonWebSignatureError,
          'The provided JSON Web Signature is invalid.',
        );
      });

      it('should not throw when the provided Signature matches the provided Message.', async () => {
        await expect(backend.verify(signature, message, publicJwk)).resolves.not.toThrow();
      });
    });
  });

  describe('EdDSA Ed448', () => {
    const publicJwk = new OctetKeyPairJsonWebKey({
      kty: 'OKP',
      crv: 'Ed448',
      x: 'vAF7jwmYardxSMxwGvWOJxphwlfMfsiKfMPFuQLXLACFUHZFnlKEbsnh78QL3yipMt0eqUurfm8A',
    });

    const privateJwk = new OctetKeyPairJsonWebKey({
      ...publicJwk.parameters,
      d: 'E4Haa6qE2nRb4OKOQdLapdEuLVIW7iIi31-oIOzxRsa1lXxz8H0LsgPtdhaZfaiLVdlV2Qt83m22',
    });

    let signature!: Buffer;

    const wrongCrvJwk = new OctetKeyPairJsonWebKey({
      kty: 'OKP',
      crv: 'X448',
      x: 'bgPeyn4Bl2SFGpWDRzLZTbTtLgCOOJKZZ3Rgn3YVIFFFAevrCVZmlIoLSZmbfmq5bwaDEjEKc0g',
      d: 'XE8wuLkWO7gsoRXSuaAnE0IzLabozrpuumvo0MrNbBtQ-0nQo23s5PKAU7md3m6qQuR1N4JxUag',
    });

    const wrongJwk = new OctetKeyPairJsonWebKey({
      kty: 'OKP',
      crv: 'Ed448',
      x: 'ed7U0-dPv9hPITi57FBLzAv9TXGZ1BvUdQ8nXWLkRvcWDzjLKLjzGjZHRp8tq7jTDuWApdt3it2A',
    });

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

      it('should throw when the provided JSON Web Key Parameter "alg" does not match the JSON Web Signature Algorithm.', async () => {
        await expect(backend.sign(message, wrongAlgJwk)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The provided JSON Web Key cannot be used by the JSON Web Signature Algorithm.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "kty" does not match the required JSON Web Key Key Type.', async () => {
        await expect(backend.sign(message, <any>wrongKtyJwk)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Signature Algorithm only accepts "OKP" JSON Web Keys.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "crv" does not match the required JSON Web Key Edwards Curve.', async () => {
        await expect(backend.sign(message, wrongCrvJwk)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Key Parameters "crv" must be "Ed25519" or "Ed448".',
        );
      });

      it('should throw when the provided JSON Web Key is not a Private Key.', async () => {
        await expect(backend.sign(message, publicJwk)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The provided JSON Web Key cannot be used to sign a Message.',
        );
      });

      it('should sign the provided Message.', async () => {
        await expect(async () => (signature = await backend.sign(message, privateJwk))).resolves.not.toThrow();

        expect(signature).toBeInstanceOf(Buffer);
        expect(signature).not.toBeEmpty();
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

      it('should throw when the provided JSON Web Key Parameter "alg" does not match the JSON Web Signature Algorithm.', async () => {
        await expect(backend.verify(signature, message, wrongAlgJwk)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The provided JSON Web Key cannot be used by the JSON Web Signature Algorithm.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "kty" does not match the required JSON Web Key Key Type.', async () => {
        await expect(backend.verify(signature, message, <any>wrongKtyJwk)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Signature Algorithm only accepts "OKP" JSON Web Keys.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "crv" does not match the required JSON Web Key Edwards Curve.', async () => {
        await expect(backend.verify(signature, message, wrongCrvJwk)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Key Parameters "crv" must be "Ed25519" or "Ed448".',
        );
      });

      it('should throw when the provided Signature is invalid.', async () => {
        await expect(backend.verify(wrongSignature, message, publicJwk)).rejects.toThrowWithMessage(
          InvalidJsonWebSignatureError,
          'The provided JSON Web Signature is invalid.',
        );
      });

      it('should throw when the provided Message is invalid.', async () => {
        await expect(backend.verify(signature, wrongMessage, publicJwk)).rejects.toThrowWithMessage(
          InvalidJsonWebSignatureError,
          'The provided JSON Web Signature is invalid.',
        );
      });

      it('should throw when the provided JSON Web Key is invalid.', async () => {
        await expect(backend.verify(signature, message, wrongJwk)).rejects.toThrowWithMessage(
          InvalidJsonWebSignatureError,
          'The provided JSON Web Signature is invalid.',
        );
      });

      it('should not throw when the provided Signature matches the provided Message.', async () => {
        await expect(backend.verify(signature, message, publicJwk)).resolves.not.toThrow();
      });
    });
  });
});
