import { Buffer } from 'buffer';
import crypto from 'crypto';

import { InvalidJoseHeaderError } from '../../../../errors/invalid-jose-header.error';
import { InvalidJsonWebEncryptionError } from '../../../../errors/invalid-jsonwebencryption.error';
import { InvalidJsonWebKeyError } from '../../../../errors/invalid-jsonwebkey.error';
import { JsonWebEncryptionHeader } from '../../../../jwe/jsonwebencryption-header';
import { JsonWebEncryptionHeaderParameters } from '../../../../jwe/jsonwebencryption-header.parameters';
import { OctetSequenceJsonWebKey } from '../../../jwk/oct/octet-sequence.jsonwebkey';
import { RsaJsonWebKey } from '../../../jwk/rsa/rsa.jsonwebkey';
import { AESGCMKWJsonWebEncryptionKeyManagementBackend } from './aesgcmkw-jsonwebencryption-key-management.backend';
import { AESGCMKWJsonWebEncryptionKeyManagementHeaderParameters } from './aesgcmkw-jsonwebencryption-key-management-header.parameters';

jest.mock<typeof crypto>('crypto', () => ({
  ...jest.requireActual('crypto'),
  randomBytes: jest.fn().mockImplementation((size, cb) => {
    cb(null, size === 12 ? Buffer.alloc(12, 0x00) : Buffer.from([...Array(size).keys()]));
  }),
}));

const invalidIvs: any[] = [
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

const invalidTags: any[] = [
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

describe('AES GCM Key Wrap JSON Web Encryption Key Management Backend', () => {
  const cek = Buffer.from('AAECAwQFBgcICQoLDA0ODw', 'base64url');

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

  describe('A128GCMKW', () => {
    const backend = new AESGCMKWJsonWebEncryptionKeyManagementBackend('A128GCMKW');

    const ek = Buffer.from('SdeFUJ2eoIvrgHBjbIy-kg', 'base64url');
    const jwk = new OctetSequenceJsonWebKey({ kty: 'oct', k: 'AAECAwQFBgcICQoLDA0ODw' });

    let wrapHeader: JsonWebEncryptionHeader<JsonWebEncryptionHeaderParameters>;
    let unwrapHeader: JsonWebEncryptionHeader<AESGCMKWJsonWebEncryptionKeyManagementHeaderParameters>;

    const wrongAlgJwk = new OctetSequenceJsonWebKey({ kty: 'oct', k: 'AAECAwQFBgcICQoLDA0ODw', alg: 'HS256' });

    const badSizeJwk = new OctetSequenceJsonWebKey({ kty: 'oct', k: 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYX' });

    const wrongEk = Buffer.from('2wIQiLNIIiuLS0gt-8cryQ', 'base64url');
    const wrongJwk = new OctetSequenceJsonWebKey({ kty: 'oct', k: 'bSc_THqy4KVV6mwfYr7t4Q' });

    const wrongIvHeader = new JsonWebEncryptionHeader<AESGCMKWJsonWebEncryptionKeyManagementHeaderParameters>({
      alg: 'A128GCMKW',
      enc: 'A128GCM',
      iv: 'AAECAwQFBgcICQoL',
      tag: '2uP2NZK_g9tW5Sh66ALzjg',
    });

    const wrongTagHeader = new JsonWebEncryptionHeader<AESGCMKWJsonWebEncryptionKeyManagementHeaderParameters>({
      alg: 'A128GCMKW',
      enc: 'A128GCM',
      iv: 'AAAAAAAAAAAAAAAA',
      tag: 'tmWkYioF468MBsE7x8EjWQ',
    });

    beforeEach(() => {
      wrapHeader = new JsonWebEncryptionHeader({ alg: 'A128GCMKW', enc: 'A128GCM' });
      unwrapHeader = new JsonWebEncryptionHeader({
        alg: 'A128GCMKW',
        enc: 'A128GCM',
        iv: 'AAAAAAAAAAAAAAAA',
        tag: '2uP2NZK_g9tW5Sh66ALzjg',
      });
    });

    describe('wrap()', () => {
      it('should throw when the provided JSON Web Key Parameter "alg" does not match the JSON Web Encryption Algorithm.', async () => {
        await expect(backend.wrap(cek, wrongAlgJwk, wrapHeader)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The provided JSON Web Key cannot be used by the JSON Web Encryption Algorithm.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "kty" does not match the required JSON Web Key Key Type.', async () => {
        await expect(backend.wrap(cek, <any>wrongKtyJwk, wrapHeader)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Encryption Algorithm only accepts "oct" JSON Web Keys.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "k" has length different than required.', async () => {
        await expect(backend.wrap(cek, badSizeJwk, wrapHeader)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Key Parameter "k" must be 16 bytes.',
        );
      });

      it('should wrap the provided Content Encryption Key.', async () => {
        await expect(backend.wrap(cek, jwk, wrapHeader)).resolves.toStrictEqual(ek);
        expect(wrapHeader).toStrictEqual(unwrapHeader);
      });
    });

    describe('unwrap()', () => {
      it('should throw when the provided JSON Web Key Parameter "alg" does not match the JSON Web Encryption Algorithm.', async () => {
        await expect(backend.unwrap(ek, wrongAlgJwk, unwrapHeader)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The provided JSON Web Key cannot be used by the JSON Web Encryption Algorithm.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "kty" does not match the required JSON Web Key Key Type.', async () => {
        await expect(backend.unwrap(ek, <any>wrongKtyJwk, unwrapHeader)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Encryption Algorithm only accepts "oct" JSON Web Keys.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "k" has length different than required.', async () => {
        await expect(backend.unwrap(ek, badSizeJwk, unwrapHeader)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Key Parameter "k" must be 16 bytes.',
        );
      });

      it.each(invalidIvs)('should throw when the provided JOSE Header Parameter "iv" is invalid.', async (iv) => {
        Reflect.set(unwrapHeader.parameters, 'iv', iv);

        await expect(backend.unwrap(ek, jwk, unwrapHeader)).rejects.toThrowWithMessage(
          InvalidJoseHeaderError,
          'Invalid JOSE Header Parameter "iv".',
        );
      });

      it.each(invalidTags)('should throw when the provided JOSE Header Parameter "tag" is invalid.', async (tag) => {
        Reflect.set(unwrapHeader.parameters, 'tag', tag);

        await expect(backend.unwrap(ek, jwk, unwrapHeader)).rejects.toThrowWithMessage(
          InvalidJoseHeaderError,
          'Invalid JOSE Header Parameter "tag".',
        );
      });

      it('should throw when the provided Encrypted Key is invalid.', async () => {
        await expect(backend.unwrap(wrongEk, jwk, unwrapHeader)).rejects.toThrowWithMessage(
          InvalidJsonWebEncryptionError,
          'The provided JSON Web Encryption is invalid.',
        );
      });

      it('should throw when the provided JSON Web Key is invalid.', async () => {
        await expect(backend.unwrap(ek, wrongJwk, unwrapHeader)).rejects.toThrowWithMessage(
          InvalidJsonWebEncryptionError,
          'The provided JSON Web Encryption is invalid.',
        );
      });

      it('should throw when providing the wrong JSON Web Encryption Header Parameter "iv".', async () => {
        await expect(backend.unwrap(ek, jwk, wrongIvHeader)).rejects.toThrowWithMessage(
          InvalidJsonWebEncryptionError,
          'The provided JSON Web Encryption is invalid.',
        );
      });

      it('should throw when providing the wrong JSON Web Encryption Header Parameter "tag".', async () => {
        await expect(backend.unwrap(ek, jwk, wrongTagHeader)).rejects.toThrowWithMessage(
          InvalidJsonWebEncryptionError,
          'The provided JSON Web Encryption is invalid.',
        );
      });

      it('should unwrap the provided Encrypted Key.', async () => {
        await expect(backend.unwrap(ek, jwk, unwrapHeader)).resolves.toStrictEqual(cek);
      });
    });

    describe('generateContentEncryptionKey()', () => {
      it('should throw when the provided JSON Web Key Parameter "alg" does not match the JSON Web Encryption Algorithm.', async () => {
        await expect(backend.generateContentEncryptionKey(wrongAlgJwk, wrapHeader)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The provided JSON Web Key cannot be used by the JSON Web Encryption Algorithm.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "kty" does not match the required JSON Web Key Key Type.', async () => {
        await expect(backend.generateContentEncryptionKey(<any>wrongKtyJwk, wrapHeader)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Encryption Algorithm only accepts "oct" JSON Web Keys.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "k" has length different than required.', async () => {
        await expect(backend.generateContentEncryptionKey(badSizeJwk, wrapHeader)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Key Parameter "k" must be 16 bytes.',
        );
      });

      it('should generate a Content Encryption Key.', async () => {
        await expect(backend.generateContentEncryptionKey(jwk, wrapHeader)).resolves.toStrictEqual(cek);
      });
    });
  });

  describe('A192GCMKW', () => {
    const backend = new AESGCMKWJsonWebEncryptionKeyManagementBackend('A192GCMKW');

    const ek = Buffer.from('2wIQiLNIIiuLS0gt-8cryQ', 'base64url');
    const jwk = new OctetSequenceJsonWebKey({ kty: 'oct', k: 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYX' });

    let wrapHeader: JsonWebEncryptionHeader;
    let unwrapHeader: JsonWebEncryptionHeader<AESGCMKWJsonWebEncryptionKeyManagementHeaderParameters>;

    const wrongAlgJwk = new OctetSequenceJsonWebKey({
      kty: 'oct',
      k: 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYX',
      alg: 'HS256',
    });

    const badSizeJwk = new OctetSequenceJsonWebKey({ kty: 'oct', k: 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8' });

    const wrongEk = Buffer.from('Dr233bEphboAoaM-FCGflg', 'base64url');
    const wrongJwk = new OctetSequenceJsonWebKey({ kty: 'oct', k: 'zaexL6bBC4lhxS1S6OEH0V6wlP1toJhh' });

    const wrongIvHeader = new JsonWebEncryptionHeader<AESGCMKWJsonWebEncryptionKeyManagementHeaderParameters>({
      alg: 'A192GCMKW',
      enc: 'A128GCM',
      iv: 'AAECAwQFBgcICQoL',
      tag: 'eUtKT7fcX5HyikEV1IHP2Q',
    });

    const wrongTagHeader = new JsonWebEncryptionHeader<AESGCMKWJsonWebEncryptionKeyManagementHeaderParameters>({
      alg: 'A192GCMKW',
      enc: 'A128GCM',
      iv: 'AAAAAAAAAAAAAAAA',
      tag: 'tmWkYioF468MBsE7x8EjWQ',
    });

    beforeEach(() => {
      wrapHeader = new JsonWebEncryptionHeader({ alg: 'A192GCMKW', enc: 'A128GCM' });
      unwrapHeader = new JsonWebEncryptionHeader({
        alg: 'A192GCMKW',
        enc: 'A128GCM',
        iv: 'AAAAAAAAAAAAAAAA',
        tag: 'eUtKT7fcX5HyikEV1IHP2Q',
      });
    });

    describe('wrap()', () => {
      it('should throw when the provided JSON Web Key Parameter "alg" does not match the JSON Web Encryption Algorithm.', async () => {
        await expect(backend.wrap(cek, wrongAlgJwk, wrapHeader)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The provided JSON Web Key cannot be used by the JSON Web Encryption Algorithm.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "kty" does not match the required JSON Web Key Key Type.', async () => {
        await expect(backend.wrap(cek, <any>wrongKtyJwk, wrapHeader)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Encryption Algorithm only accepts "oct" JSON Web Keys.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "k" has length different than required.', async () => {
        await expect(backend.wrap(cek, badSizeJwk, wrapHeader)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Key Parameter "k" must be 24 bytes.',
        );
      });

      it('should wrap the provided Content Encryption Key.', async () => {
        await expect(backend.wrap(cek, jwk, wrapHeader)).resolves.toStrictEqual(ek);
        expect(wrapHeader).toStrictEqual(unwrapHeader);
      });
    });

    describe('unwrap()', () => {
      it('should throw when the provided JSON Web Key Parameter "alg" does not match the JSON Web Encryption Algorithm.', async () => {
        await expect(backend.unwrap(ek, wrongAlgJwk, unwrapHeader)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The provided JSON Web Key cannot be used by the JSON Web Encryption Algorithm.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "kty" does not match the required JSON Web Key Key Type.', async () => {
        await expect(backend.unwrap(ek, <any>wrongKtyJwk, unwrapHeader)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Encryption Algorithm only accepts "oct" JSON Web Keys.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "k" has length different than required.', async () => {
        await expect(backend.unwrap(ek, badSizeJwk, unwrapHeader)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Key Parameter "k" must be 24 bytes.',
        );
      });

      it.each(invalidIvs)('should throw when the provided JOSE Header Parameter "iv" is invalid.', async (iv) => {
        Reflect.set(unwrapHeader.parameters, 'iv', iv);

        await expect(backend.unwrap(ek, jwk, unwrapHeader)).rejects.toThrowWithMessage(
          InvalidJoseHeaderError,
          'Invalid JOSE Header Parameter "iv".',
        );
      });

      it.each(invalidTags)('should throw when the provided JOSE Header Parameter "tag" is invalid.', async (tag) => {
        Reflect.set(unwrapHeader.parameters, 'tag', tag);

        await expect(backend.unwrap(ek, jwk, unwrapHeader)).rejects.toThrowWithMessage(
          InvalidJoseHeaderError,
          'Invalid JOSE Header Parameter "tag".',
        );
      });

      it('should throw when the provided Encrypted Key is invalid.', async () => {
        await expect(backend.unwrap(wrongEk, jwk, unwrapHeader)).rejects.toThrowWithMessage(
          InvalidJsonWebEncryptionError,
          'The provided JSON Web Encryption is invalid.',
        );
      });

      it('should throw when the provided JSON Web Key is invalid.', async () => {
        await expect(backend.unwrap(ek, wrongJwk, unwrapHeader)).rejects.toThrowWithMessage(
          InvalidJsonWebEncryptionError,
          'The provided JSON Web Encryption is invalid.',
        );
      });

      it('should throw when providing the wrong JSON Web Encryption Header Parameter "iv".', async () => {
        await expect(backend.unwrap(ek, jwk, wrongIvHeader)).rejects.toThrowWithMessage(
          InvalidJsonWebEncryptionError,
          'The provided JSON Web Encryption is invalid.',
        );
      });

      it('should throw when providing the wrong JSON Web Encryption Header Parameter "tag".', async () => {
        await expect(backend.unwrap(ek, jwk, wrongTagHeader)).rejects.toThrowWithMessage(
          InvalidJsonWebEncryptionError,
          'The provided JSON Web Encryption is invalid.',
        );
      });

      it('should unwrap the provided Encrypted Key.', async () => {
        await expect(backend.unwrap(ek, jwk, unwrapHeader)).resolves.toStrictEqual(cek);
      });
    });

    describe('generateContentEncryptionKey()', () => {
      it('should throw when the provided JSON Web Key Parameter "alg" does not match the JSON Web Encryption Algorithm.', async () => {
        await expect(backend.generateContentEncryptionKey(wrongAlgJwk, wrapHeader)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The provided JSON Web Key cannot be used by the JSON Web Encryption Algorithm.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "kty" does not match the required JSON Web Key Key Type.', async () => {
        await expect(backend.generateContentEncryptionKey(<any>wrongKtyJwk, wrapHeader)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Encryption Algorithm only accepts "oct" JSON Web Keys.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "k" has length different than required.', async () => {
        await expect(backend.generateContentEncryptionKey(badSizeJwk, wrapHeader)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Key Parameter "k" must be 24 bytes.',
        );
      });

      it('should generate a Content Encryption Key.', async () => {
        await expect(backend.generateContentEncryptionKey(jwk, wrapHeader)).resolves.toStrictEqual(cek);
      });
    });
  });

  describe('A256GCMKW', () => {
    const backend = new AESGCMKWJsonWebEncryptionKeyManagementBackend('A256GCMKW');

    const ek = Buffer.from('Dr233bEphboAoaM-FCGflg', 'base64url');
    const jwk = new OctetSequenceJsonWebKey({ kty: 'oct', k: 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8' });

    let wrapHeader: JsonWebEncryptionHeader;
    let unwrapHeader: JsonWebEncryptionHeader<AESGCMKWJsonWebEncryptionKeyManagementHeaderParameters>;

    const wrongAlgJwk = new OctetSequenceJsonWebKey({
      kty: 'oct',
      k: 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8',
      alg: 'HS256',
    });

    const badSizeJwk = new OctetSequenceJsonWebKey({ kty: 'oct', k: 'AAECAwQFBgcICQoLDA0ODw' });

    const wrongEk = Buffer.from('SdeFUJ2eoIvrgHBjbIy-kg', 'base64url');
    const wrongJwk = new OctetSequenceJsonWebKey({ kty: 'oct', k: 'kIIor71zWjtNVXzalbKbjMU8whvBKQADD3IDRSh6Y7s' });

    const wrongIvHeader = new JsonWebEncryptionHeader<AESGCMKWJsonWebEncryptionKeyManagementHeaderParameters>({
      alg: 'A256GCMKW',
      enc: 'A128GCM',
      iv: 'AAECAwQFBgcICQoL',
      tag: 'KmK4cS6zJo9GwEweS9DtQA',
    });

    const wrongTagHeader = new JsonWebEncryptionHeader<AESGCMKWJsonWebEncryptionKeyManagementHeaderParameters>({
      alg: 'A256GCMKW',
      enc: 'A128GCM',
      iv: 'AAAAAAAAAAAAAAAA',
      tag: 'tmWkYioF468MBsE7x8EjWQ',
    });

    beforeEach(() => {
      wrapHeader = new JsonWebEncryptionHeader({ alg: 'A256GCMKW', enc: 'A128GCM' });
      unwrapHeader = new JsonWebEncryptionHeader({
        alg: 'A256GCMKW',
        enc: 'A128GCM',
        iv: 'AAAAAAAAAAAAAAAA',
        tag: 'KmK4cS6zJo9GwEweS9DtQA',
      });
    });

    describe('wrap()', () => {
      it('should throw when the provided JSON Web Key Parameter "alg" does not match the JSON Web Encryption Algorithm.', async () => {
        await expect(backend.wrap(cek, wrongAlgJwk, wrapHeader)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The provided JSON Web Key cannot be used by the JSON Web Encryption Algorithm.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "kty" does not match the required JSON Web Key Key Type.', async () => {
        await expect(backend.wrap(cek, <any>wrongKtyJwk, wrapHeader)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Encryption Algorithm only accepts "oct" JSON Web Keys.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "k" has length different than required.', async () => {
        await expect(backend.wrap(cek, badSizeJwk, wrapHeader)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Key Parameter "k" must be 32 bytes.',
        );
      });

      it('should wrap the provided Content Encryption Key.', async () => {
        await expect(backend.wrap(cek, jwk, wrapHeader)).resolves.toStrictEqual(ek);
        expect(wrapHeader).toStrictEqual(unwrapHeader);
      });
    });

    describe('unwrap()', () => {
      it('should throw when the provided JSON Web Key Parameter "alg" does not match the JSON Web Encryption Algorithm.', async () => {
        await expect(backend.unwrap(ek, wrongAlgJwk, unwrapHeader)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The provided JSON Web Key cannot be used by the JSON Web Encryption Algorithm.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "kty" does not match the required JSON Web Key Key Type.', async () => {
        await expect(backend.unwrap(ek, <any>wrongKtyJwk, unwrapHeader)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Encryption Algorithm only accepts "oct" JSON Web Keys.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "k" has length different than required.', async () => {
        await expect(backend.unwrap(ek, badSizeJwk, unwrapHeader)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Key Parameter "k" must be 32 bytes.',
        );
      });

      it.each(invalidIvs)('should throw when the provided JOSE Header Parameter "iv" is invalid.', async (iv) => {
        Reflect.set(unwrapHeader.parameters, 'iv', iv);

        await expect(backend.unwrap(ek, jwk, unwrapHeader)).rejects.toThrowWithMessage(
          InvalidJoseHeaderError,
          'Invalid JOSE Header Parameter "iv".',
        );
      });

      it.each(invalidTags)('should throw when the provided JOSE Header Parameter "tag" is invalid.', async (tag) => {
        Reflect.set(unwrapHeader.parameters, 'tag', tag);

        await expect(backend.unwrap(ek, jwk, unwrapHeader)).rejects.toThrowWithMessage(
          InvalidJoseHeaderError,
          'Invalid JOSE Header Parameter "tag".',
        );
      });

      it('should throw when the provided Encrypted Key is invalid.', async () => {
        await expect(backend.unwrap(wrongEk, jwk, unwrapHeader)).rejects.toThrowWithMessage(
          InvalidJsonWebEncryptionError,
          'The provided JSON Web Encryption is invalid.',
        );
      });

      it('should throw when the provided JSON Web Key is invalid.', async () => {
        await expect(backend.unwrap(ek, wrongJwk, unwrapHeader)).rejects.toThrowWithMessage(
          InvalidJsonWebEncryptionError,
          'The provided JSON Web Encryption is invalid.',
        );
      });

      it('should throw when providing the wrong JSON Web Encryption Header Parameter "iv".', async () => {
        await expect(backend.unwrap(ek, jwk, wrongIvHeader)).rejects.toThrowWithMessage(
          InvalidJsonWebEncryptionError,
          'The provided JSON Web Encryption is invalid.',
        );
      });

      it('should throw when providing the wrong JSON Web Encryption Header Parameter "tag".', async () => {
        await expect(backend.unwrap(ek, jwk, wrongTagHeader)).rejects.toThrowWithMessage(
          InvalidJsonWebEncryptionError,
          'The provided JSON Web Encryption is invalid.',
        );
      });

      it('should unwrap the provided Encrypted Key.', async () => {
        await expect(backend.unwrap(ek, jwk, unwrapHeader)).resolves.toStrictEqual(cek);
      });
    });

    describe('generateContentEncryptionKey()', () => {
      it('should throw when the provided JSON Web Key Parameter "alg" does not match the JSON Web Encryption Algorithm.', async () => {
        await expect(backend.generateContentEncryptionKey(wrongAlgJwk, wrapHeader)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The provided JSON Web Key cannot be used by the JSON Web Encryption Algorithm.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "kty" does not match the required JSON Web Key Key Type.', async () => {
        await expect(backend.generateContentEncryptionKey(<any>wrongKtyJwk, wrapHeader)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Encryption Algorithm only accepts "oct" JSON Web Keys.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "k" has length different than required.', async () => {
        await expect(backend.generateContentEncryptionKey(badSizeJwk, wrapHeader)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Key Parameter "k" must be 32 bytes.',
        );
      });

      it('should generate a Content Encryption Key.', async () => {
        await expect(backend.generateContentEncryptionKey(jwk, wrapHeader)).resolves.toStrictEqual(cek);
      });
    });
  });
});
