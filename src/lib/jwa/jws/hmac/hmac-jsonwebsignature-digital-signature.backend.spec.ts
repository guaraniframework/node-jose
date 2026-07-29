import { Buffer } from 'buffer';

import { InvalidJsonWebKeyError } from '../../../errors/invalid-jsonwebkey.error';
import { InvalidJsonWebSignatureError } from '../../../errors/invalid-jsonwebsignature.error';
import { OctetSequenceJsonWebKey } from '../../jwk/oct/octet-sequence.jsonwebkey';
import { RsaJsonWebKey } from '../../jwk/rsa/rsa.jsonwebkey';
import { HMACJsonWebSignatureDigitalSignatureBackend } from './hmac-jsonwebsignature-digital-signature.backend';

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

describe('HMAC JSON Web Signature Digital Signature Backend.', () => {
  const message = Buffer.from('Super secret message.', 'utf8');

  const wrongAlgJwk = new OctetSequenceJsonWebKey({
    kty: 'oct',
    k: 'qDM80igvja4Tg_tNsEuWDhl2bMM6_NgJEldFhIEuwqQ',
    alg: 'A128GCMKW',
  });

  const wrongKtyJwk = new RsaJsonWebKey({
    kty: 'RSA',
    n:
      'xjpFydzTbByzL5jhEa2yQO63dpS9d9SKaN107AR69skKiTR4uK1c4SzDt4YcurDB' +
      'yhgKNzeBo6Vq3IRrkrltp97LKWfeZdM-leGt8-UTZEWqrNf3UGOEj8kI6lbjiG-S' +
      'n_yNHcVA9qBV22norZkgXctHLeFbY6TmpD-I8_UiplZUHoc9KlYc7crCQRa-O7tK' +
      'FDULNTMjjifc0dmuYP7ZcYAZXmRmoOpQuDr8s7OZY7TAqN0btMfA7RpUCWLT6TMR' +
      'QPX8GcyTxfbkOrSTFueKMHVNdXDtl068XXJ9mkjORiEmwlzqSBoxdeLWcNf_u20S' +
      '5JG5iK0nsm1uZYu-02XN-w',
    e: 'AQAB',
  });

  const wrongMessage = Buffer.from('Bad message.', 'utf8');

  describe('HS256', () => {
    const backend = new HMACJsonWebSignatureDigitalSignatureBackend('HS256');

    const jwk = new OctetSequenceJsonWebKey({
      kty: 'oct',
      k: 'qDM80igvja4Tg_tNsEuWDhl2bMM6_NgJEldFhIEuwqQ',
    });

    const signature = Buffer.from('oYyAwnx7D5WIo3L1WWx_zBSNX12nH8lwXQHgpPiApSk', 'base64url');

    const smallJwk = new OctetSequenceJsonWebKey({ kty: 'oct', k: '_Q-5ANzs2BQcquIFnnG8bg' });

    const wrongSignatures = [Buffer.alloc(0), Buffer.from('HAsYK0fb8ZooUQW4Lu1BdxEV5Ce4Pl1As7JypupdBDs', 'base64url')];
    const wrongJwk = new OctetSequenceJsonWebKey({
      kty: 'oct',
      k: 'wSWnJGjdIe06lRs2ITPAsFeLiVoiQGbaz415daD5kOc',
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
          'The JSON Web Signature Algorithm only accepts "oct" JSON Web Keys.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "k" has length smaller than required.', async () => {
        await expect(backend.sign(message, smallJwk)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Key Parameter "k" must be at least 32 bytes.',
        );
      });

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

      it('should throw when the provided JSON Web Key Parameter "alg" does not match the JSON Web Signature Algorithm.', async () => {
        await expect(backend.verify(signature, message, wrongAlgJwk)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The provided JSON Web Key cannot be used by the JSON Web Signature Algorithm.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "kty" does not match the required JSON Web Key Key Type.', async () => {
        await expect(backend.verify(signature, message, <any>wrongKtyJwk)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Signature Algorithm only accepts "oct" JSON Web Keys.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "k" has length smaller than required.', async () => {
        await expect(backend.verify(signature, message, smallJwk)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Key Parameter "k" must be at least 32 bytes.',
        );
      });

      it.each(wrongSignatures)('should throw when the provided Signature is invalid.', async (wrongSignature) => {
        await expect(backend.verify(wrongSignature, message, jwk)).rejects.toThrowWithMessage(
          InvalidJsonWebSignatureError,
          'The provided JSON Web Signature is invalid.',
        );
      });

      it('should throw when the provided Message is invalid.', async () => {
        await expect(backend.verify(signature, wrongMessage, jwk)).rejects.toThrowWithMessage(
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
        await expect(backend.verify(signature, message, jwk)).resolves.not.toThrow();
      });
    });
  });

  describe('HS384', () => {
    const backend = new HMACJsonWebSignatureDigitalSignatureBackend('HS384');

    const jwk = new OctetSequenceJsonWebKey({
      kty: 'oct',
      k: 'StbWgZZh28xbcPHFlyX9I4obVOyoATxvnCGRn1W3bBhnL6eUppMxBLmU4FmfkUTX',
    });

    const signature = Buffer.from('T6XdAl5A0a28AXqtCiLM_ibT46yce8xl4C-x__EV4zgd5R1OnUsIpvFL-rm0SM8o', 'base64url');

    const smallJwk = new OctetSequenceJsonWebKey({ kty: 'oct', k: 'VVqcFoBmovm5xodv6FmUkNboA0mVuhAW' });

    const wrongSignatures = [
      Buffer.alloc(0),
      Buffer.from('1XAMTYwm3gVDQ4FyPmzeE0NqC1zfKrQjmAsd1Mb_MBke-O5wiQBVKLhGK1zhPFlR', 'base64url'),
    ];

    const wrongJwk = new OctetSequenceJsonWebKey({
      kty: 'oct',
      k: 'pBZgPlQEOyzG1CRdKqoKexs2B23rbZVNhWilR-PAAF6bWF70B1EActiCKZlcdOEC',
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
          'The JSON Web Signature Algorithm only accepts "oct" JSON Web Keys.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "k" has length smaller than required.', async () => {
        await expect(backend.sign(message, smallJwk)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Key Parameter "k" must be at least 48 bytes.',
        );
      });

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

      it('should throw when the provided JSON Web Key Parameter "alg" does not match the JSON Web Signature Algorithm.', async () => {
        await expect(backend.verify(signature, message, wrongAlgJwk)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The provided JSON Web Key cannot be used by the JSON Web Signature Algorithm.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "kty" does not match the required JSON Web Key Key Type.', async () => {
        await expect(backend.verify(signature, message, <any>wrongKtyJwk)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Signature Algorithm only accepts "oct" JSON Web Keys.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "k" has length smaller than required.', async () => {
        await expect(backend.verify(signature, message, smallJwk)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Key Parameter "k" must be at least 48 bytes.',
        );
      });

      it.each(wrongSignatures)('should throw when the provided Signature is invalid.', async (wrongSignature) => {
        await expect(backend.verify(wrongSignature, message, jwk)).rejects.toThrowWithMessage(
          InvalidJsonWebSignatureError,
          'The provided JSON Web Signature is invalid.',
        );
      });

      it('should throw when the provided Message is invalid.', async () => {
        await expect(backend.verify(signature, wrongMessage, jwk)).rejects.toThrowWithMessage(
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
        await expect(backend.verify(signature, message, jwk)).resolves.not.toThrow();
      });
    });
  });

  describe('HS512', () => {
    const backend = new HMACJsonWebSignatureDigitalSignatureBackend('HS512');

    const jwk = new OctetSequenceJsonWebKey({
      kty: 'oct',
      k: 'la7U9KFcv2g17jSil25USwufXL2J_5UtDadwtcIUOU40n93dzZtwKpwajuqd9XMvGW1K_vn2_ygwbZUM7oAuOw',
    });

    const signature = Buffer.from(
      '8oHNB6v-xcTecQ22og2IVpThVQnj6ac8t3p60mxVqdpNE-QmXe9hdvJZ9YE2FieemCSWEbpwQiqJxsE-9qzKHA',
      'base64url',
    );

    const smallJwk = new OctetSequenceJsonWebKey({ kty: 'oct', k: '_YXVGItuB0nw8FV-nf0WRb9tEaGy7VrlhIp0xDApPOA' });

    const wrongSignatures = [
      Buffer.alloc(0),
      Buffer.from(
        'v2Lsta403z2PvG-DgWwO62Q60HnMyrozAgcM0u1Vh-y7QrgImA9ySvFPpyz-fbkORv4K3sEnhlhVe5E6tKZgFA',
        'base64url',
      ),
    ];

    const wrongJwk = new OctetSequenceJsonWebKey({
      kty: 'oct',
      k: 'SF3XK31tgbhk2P0pSHwy3ZEEOAooafH4u6W6HX__vIX4eZi-IheJQv_LoTt0OouC03VCUFBTdwNJRxDnYSGV2Q',
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
          'The JSON Web Signature Algorithm only accepts "oct" JSON Web Keys.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "k" has length smaller than required.', async () => {
        await expect(backend.sign(message, smallJwk)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Key Parameter "k" must be at least 64 bytes.',
        );
      });

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

      it('should throw when the provided JSON Web Key Parameter "alg" does not match the JSON Web Signature Algorithm.', async () => {
        await expect(backend.verify(signature, message, wrongAlgJwk)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The provided JSON Web Key cannot be used by the JSON Web Signature Algorithm.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "kty" does not match the required JSON Web Key Key Type.', async () => {
        await expect(backend.verify(signature, message, <any>wrongKtyJwk)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Signature Algorithm only accepts "oct" JSON Web Keys.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "k" has length smaller than required.', async () => {
        await expect(backend.verify(signature, message, smallJwk)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Key Parameter "k" must be at least 64 bytes.',
        );
      });

      it.each(wrongSignatures)('should throw when the provided Signature is invalid.', async (wrongSignature) => {
        await expect(backend.verify(wrongSignature, message, jwk)).rejects.toThrowWithMessage(
          InvalidJsonWebSignatureError,
          'The provided JSON Web Signature is invalid.',
        );
      });

      it('should throw when the provided Message is invalid.', async () => {
        await expect(backend.verify(signature, wrongMessage, jwk)).rejects.toThrowWithMessage(
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
        await expect(backend.verify(signature, message, jwk)).resolves.not.toThrow();
      });
    });
  });
});
