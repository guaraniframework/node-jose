import { Buffer } from 'buffer';
import crypto from 'crypto';

import { InvalidJoseHeaderError } from '../../../../errors/invalid-jose-header.error';
import { InvalidJsonWebEncryptionError } from '../../../../errors/invalid-jsonwebencryption.error';
import { InvalidJsonWebKeyError } from '../../../../errors/invalid-jsonwebkey.error';
import { JsonWebEncryptionHeader } from '../../../../jwe/jsonwebencryption-header';
import { OctetSequenceJsonWebKey } from '../../../jwk/oct/octet-sequence.jsonwebkey';
import { OctetKeyPairJsonWebKey } from '../../../jwk/okp/octet-key-pair.jsonwebkey';
import { AESKWJsonWebEncryptionKeyManagementBackend } from '../aeskw/aeskw-jsonwebencryption-key-management.backend';
import { KeyManagementAlgorithm } from '../key-management-algorithm.type';
import { PBES2JsonWebEncryptionKeyManagementBackend } from './pbes2-jsonwebencryption-key-management.backend';
import { PBES2JsonWebEncryptionKeyManagementHeaderParameters } from './pbes2-jsonwebencryption-key-management-header.parameters';

const cek = Buffer.from('bxsZNEIdFE5csDjwQdBScKGDJDfK7LmsgReZwsMw_bY', 'base64url');

jest.mock<typeof crypto>('crypto', () => ({
  ...jest.requireActual('crypto'),
  randomBytes: jest.fn().mockImplementation((size, cb) => (size === 32 ? cb(null, cek) : cb(new Error(), null))),
}));

const invalidP2Ss: any[] = [
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
  '1234567',
];

const invalidP2Cs: any[] = [
  undefined,
  null,
  true,
  1n,
  'a',
  Symbol('a'),
  Buffer,
  Buffer.alloc(1),
  () => 1,
  {},
  [],
  1.2,
  999,
];

describe('PBES2 JSON Web Encryption Key Management Backend', () => {
  const jwk = new OctetSequenceJsonWebKey({
    kty: 'oct',
    k: Buffer.from('Thus from my lips, by yours, my sin is purged.', 'utf8').toString('base64url'),
  });

  const wrongAlgJwk = new OctetSequenceJsonWebKey({
    kty: 'oct',
    k: 'qDM80igvja4Tg_tNsEuWDhl2bMM6_NgJEldFhIEuwqQ',
    alg: 'HS256',
  });

  const wrongKtyJwk = new OctetKeyPairJsonWebKey({
    kty: 'OKP',
    crv: 'Ed25519',
    x: 'g5p3LK1Mpb1lFnBDRlwvZPZSOnbGFSKnyngC7AOAsgE',
  });

  const wrongEk = Buffer.from('ZYr4n0Jg_9jOaXA4TZ0SXYjz7DDk-x7NG_PSW31YwzkRll1FzRbT-g', 'base64url');

  beforeEach(() => {
    jest.restoreAllMocks();
  });

  describe('PBES2-HS256+A128KW', () => {
    const backend = new PBES2JsonWebEncryptionKeyManagementBackend('PBES2-HS256+A128KW');

    const ek = Buffer.from('TrqXOwuNUfDV9VPTNbyGvEJ9JMjefAVn-TR1uIxR9p6hsRQh9Tk7BA', 'base64url');

    let header: JsonWebEncryptionHeader<PBES2JsonWebEncryptionKeyManagementHeaderParameters>;

    const wrongJwk = new OctetSequenceJsonWebKey({
      kty: 'oct',
      k: Buffer.from('Bad password.', 'utf8').toString('base64url'),
    });

    const wrongP2SHeader = new JsonWebEncryptionHeader<PBES2JsonWebEncryptionKeyManagementHeaderParameters>({
      alg: 'PBES2-HS256+A128KW',
      enc: 'A128CBC-HS256',
      p2s: 'QpGYnmJUuIdGFzIzaiEvJw',
      p2c: 4096,
    });

    const wrongP2CHeader = new JsonWebEncryptionHeader<PBES2JsonWebEncryptionKeyManagementHeaderParameters>({
      alg: 'PBES2-HS256+A128KW',
      enc: 'A128CBC-HS256',
      p2s: '2WCTcJZ1Rvd_CJuJripQ1w',
      p2c: 8192,
    });

    beforeEach(() => {
      header = new JsonWebEncryptionHeader<PBES2JsonWebEncryptionKeyManagementHeaderParameters>({
        alg: 'PBES2-HS256+A128KW',
        enc: 'A128CBC-HS256',
        p2s: '2WCTcJZ1Rvd_CJuJripQ1w',
        p2c: 4096,
      });
    });

    describe('constructor', () => {
      it('should have a 128-bit AES Key Wrap JSON Web Encryption Key Management Backend.', () => {
        expect(backend['aeskwBackend']).toBeInstanceOf(AESKWJsonWebEncryptionKeyManagementBackend);
        expect(backend['aeskwBackend']!['algorithm']).toBe<KeyManagementAlgorithm>('A128KW');
      });
    });

    describe('wrap()', () => {
      it('should throw when the provided JSON Web Key Parameter "alg" does not match the JSON Web Encryption Algorithm.', async () => {
        await expect(backend.wrap(cek, wrongAlgJwk, header)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The provided JSON Web Key cannot be used by the JSON Web Encryption Algorithm.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "kty" does not match the required JSON Web Key Key Type.', async () => {
        await expect(backend.wrap(cek, <any>wrongKtyJwk, header)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Encryption Algorithm only accepts "oct" JSON Web Keys.',
        );
      });

      it.each(invalidP2Ss)('should throw when the provided JOSE Header Parameter "p2s" is invalid.', async (p2s) => {
        Reflect.set(header.parameters, 'p2s', p2s);

        await expect(backend.wrap(cek, jwk, header)).rejects.toThrowWithMessage(
          InvalidJoseHeaderError,
          'Invalid JOSE Header Parameter "p2s".',
        );
      });

      it.each(invalidP2Cs)('should throw when the provided JOSE Header Parameter "p2c" is invalid.', async (p2c) => {
        Reflect.set(header.parameters, 'p2c', p2c);

        await expect(backend.wrap(cek, jwk, header)).rejects.toThrowWithMessage(
          InvalidJoseHeaderError,
          'Invalid JOSE Header Parameter "p2c".',
        );
      });

      it('should wrap the provided Content Encryption Key.', async () => {
        const wrapSpy = jest.spyOn(backend['aeskwBackend'], 'wrap');
        await expect(backend.wrap(cek, jwk, header)).resolves.toStrictEqual(ek);
        expect(wrapSpy).toHaveBeenCalledOnce();
      });
    });

    describe('unwrap()', () => {
      it('should throw when the provided JSON Web Key Parameter "alg" does not match the JSON Web Encryption Algorithm.', async () => {
        await expect(backend.unwrap(ek, wrongAlgJwk, header)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The provided JSON Web Key cannot be used by the JSON Web Encryption Algorithm.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "kty" does not match the required JSON Web Key Key Type.', async () => {
        await expect(backend.unwrap(ek, <any>wrongKtyJwk, header)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Encryption Algorithm only accepts "oct" JSON Web Keys.',
        );
      });

      it.each(invalidP2Ss)('should throw when the provided JOSE Header Parameter "p2s" is invalid.', async (p2s) => {
        Reflect.set(header.parameters, 'p2s', p2s);

        await expect(backend.unwrap(ek, jwk, header)).rejects.toThrowWithMessage(
          InvalidJoseHeaderError,
          'Invalid JOSE Header Parameter "p2s".',
        );
      });

      it.each(invalidP2Cs)('should throw when the provided JOSE Header Parameter "p2c" is invalid.', async (p2c) => {
        Reflect.set(header.parameters, 'p2c', p2c);

        await expect(backend.unwrap(ek, jwk, header)).rejects.toThrowWithMessage(
          InvalidJoseHeaderError,
          'Invalid JOSE Header Parameter "p2c".',
        );
      });

      it('should throw when the provided Encrypted Key is invalid.', async () => {
        await expect(backend.unwrap(wrongEk, jwk, header)).rejects.toThrowWithMessage(
          InvalidJsonWebEncryptionError,
          'The provided JSON Web Encryption is invalid.',
        );
      });

      it('should throw when the provided JSON Web Key is invalid.', async () => {
        await expect(backend.unwrap(ek, wrongJwk, header)).rejects.toThrowWithMessage(
          InvalidJsonWebEncryptionError,
          'The provided JSON Web Encryption is invalid.',
        );
      });

      it('should throw when providing the wrong JSON Web Encryption Header Parameter "iv".', async () => {
        await expect(backend.unwrap(ek, jwk, wrongP2SHeader)).rejects.toThrowWithMessage(
          InvalidJsonWebEncryptionError,
          'The provided JSON Web Encryption is invalid.',
        );
      });

      it('should throw when providing the wrong JSON Web Encryption Header Parameter "tag".', async () => {
        await expect(backend.unwrap(ek, jwk, wrongP2CHeader)).rejects.toThrowWithMessage(
          InvalidJsonWebEncryptionError,
          'The provided JSON Web Encryption is invalid.',
        );
      });

      it('should unwrap the provided Encrypted Key.', async () => {
        const unwrapSpy = jest.spyOn(backend['aeskwBackend'], 'unwrap');
        await expect(backend.unwrap(ek, jwk, header)).resolves.toStrictEqual(cek);
        expect(unwrapSpy).toHaveBeenCalledOnce();
      });
    });

    describe('generateContentEncryptionKey()', () => {
      it('should throw when the provided JSON Web Key Parameter "alg" does not match the JSON Web Encryption Algorithm.', async () => {
        await expect(backend.generateContentEncryptionKey(wrongAlgJwk, header)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The provided JSON Web Key cannot be used by the JSON Web Encryption Algorithm.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "kty" does not match the required JSON Web Key Key Type.', async () => {
        await expect(backend.generateContentEncryptionKey(<any>wrongKtyJwk, header)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Encryption Algorithm only accepts "oct" JSON Web Keys.',
        );
      });

      it('should generate a Content Encryption Key.', async () => {
        await expect(backend.generateContentEncryptionKey(jwk, header)).resolves.toStrictEqual(cek);
      });
    });
  });

  describe('PBES2-HS384+A192KW', () => {
    const backend = new PBES2JsonWebEncryptionKeyManagementBackend('PBES2-HS384+A192KW');

    const ek = Buffer.from('QaWVsah2J1z6QQCWWF98wGuf-NB8lmsJyeLY7WxW5MtiCePRBTNbMA', 'base64url');

    let header: JsonWebEncryptionHeader<PBES2JsonWebEncryptionKeyManagementHeaderParameters>;

    const wrongJwk = new OctetSequenceJsonWebKey({
      kty: 'oct',
      k: Buffer.from('Bad password.', 'utf8').toString('base64url'),
    });

    const wrongP2SHeader = new JsonWebEncryptionHeader<PBES2JsonWebEncryptionKeyManagementHeaderParameters>({
      alg: 'PBES2-HS384+A192KW',
      enc: 'A128CBC-HS256',
      p2s: 'QpGYnmJUuIdGFzIzaiEvJw',
      p2c: 4096,
    });

    const wrongP2CHeader = new JsonWebEncryptionHeader<PBES2JsonWebEncryptionKeyManagementHeaderParameters>({
      alg: 'PBES2-HS384+A192KW',
      enc: 'A128CBC-HS256',
      p2s: '2WCTcJZ1Rvd_CJuJripQ1w',
      p2c: 8192,
    });

    beforeEach(() => {
      header = new JsonWebEncryptionHeader<PBES2JsonWebEncryptionKeyManagementHeaderParameters>({
        alg: 'PBES2-HS384+A192KW',
        enc: 'A128CBC-HS256',
        p2s: '2WCTcJZ1Rvd_CJuJripQ1w',
        p2c: 4096,
      });
    });

    describe('constructor', () => {
      it('should have a 192-bit AES Key Wrap JSON Web Encryption Key Management Backend.', () => {
        expect(backend['aeskwBackend']).toBeInstanceOf(AESKWJsonWebEncryptionKeyManagementBackend);
        expect(backend['aeskwBackend']!['algorithm']).toBe<KeyManagementAlgorithm>('A192KW');
      });
    });

    describe('wrap()', () => {
      it('should throw when the provided JSON Web Key Parameter "alg" does not match the JSON Web Encryption Algorithm.', async () => {
        await expect(backend.wrap(cek, wrongAlgJwk, header)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The provided JSON Web Key cannot be used by the JSON Web Encryption Algorithm.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "kty" does not match the required JSON Web Key Key Type.', async () => {
        await expect(backend.wrap(cek, <any>wrongKtyJwk, header)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Encryption Algorithm only accepts "oct" JSON Web Keys.',
        );
      });

      it.each(invalidP2Ss)('should throw when the provided JOSE Header Parameter "p2s" is invalid.', async (p2s) => {
        Reflect.set(header.parameters, 'p2s', p2s);

        await expect(backend.wrap(cek, jwk, header)).rejects.toThrowWithMessage(
          InvalidJoseHeaderError,
          'Invalid JOSE Header Parameter "p2s".',
        );
      });

      it.each(invalidP2Cs)('should throw when the provided JOSE Header Parameter "p2c" is invalid.', async (p2c) => {
        Reflect.set(header.parameters, 'p2c', p2c);

        await expect(backend.wrap(cek, jwk, header)).rejects.toThrowWithMessage(
          InvalidJoseHeaderError,
          'Invalid JOSE Header Parameter "p2c".',
        );
      });

      it('should wrap the provided Content Encryption Key.', async () => {
        const wrapSpy = jest.spyOn(backend['aeskwBackend'], 'wrap');
        await expect(backend.wrap(cek, jwk, header)).resolves.toStrictEqual(ek);
        expect(wrapSpy).toHaveBeenCalledOnce();
      });
    });

    describe('unwrap()', () => {
      it('should throw when the provided JSON Web Key Parameter "alg" does not match the JSON Web Encryption Algorithm.', async () => {
        await expect(backend.unwrap(ek, wrongAlgJwk, header)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The provided JSON Web Key cannot be used by the JSON Web Encryption Algorithm.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "kty" does not match the required JSON Web Key Key Type.', async () => {
        await expect(backend.unwrap(ek, <any>wrongKtyJwk, header)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Encryption Algorithm only accepts "oct" JSON Web Keys.',
        );
      });

      it.each(invalidP2Ss)('should throw when the provided JOSE Header Parameter "p2s" is invalid.', async (p2s) => {
        Reflect.set(header.parameters, 'p2s', p2s);

        await expect(backend.unwrap(ek, jwk, header)).rejects.toThrowWithMessage(
          InvalidJoseHeaderError,
          'Invalid JOSE Header Parameter "p2s".',
        );
      });

      it.each(invalidP2Cs)('should throw when the provided JOSE Header Parameter "p2c" is invalid.', async (p2c) => {
        Reflect.set(header.parameters, 'p2c', p2c);

        await expect(backend.unwrap(ek, jwk, header)).rejects.toThrowWithMessage(
          InvalidJoseHeaderError,
          'Invalid JOSE Header Parameter "p2c".',
        );
      });

      it('should throw when the provided Encrypted Key is invalid.', async () => {
        await expect(backend.unwrap(wrongEk, jwk, header)).rejects.toThrowWithMessage(
          InvalidJsonWebEncryptionError,
          'The provided JSON Web Encryption is invalid.',
        );
      });

      it('should throw when the provided JSON Web Key is invalid.', async () => {
        await expect(backend.unwrap(ek, wrongJwk, header)).rejects.toThrowWithMessage(
          InvalidJsonWebEncryptionError,
          'The provided JSON Web Encryption is invalid.',
        );
      });

      it('should throw when providing the wrong JSON Web Encryption Header Parameter "iv".', async () => {
        await expect(backend.unwrap(ek, jwk, wrongP2SHeader)).rejects.toThrowWithMessage(
          InvalidJsonWebEncryptionError,
          'The provided JSON Web Encryption is invalid.',
        );
      });

      it('should throw when providing the wrong JSON Web Encryption Header Parameter "tag".', async () => {
        await expect(backend.unwrap(ek, jwk, wrongP2CHeader)).rejects.toThrowWithMessage(
          InvalidJsonWebEncryptionError,
          'The provided JSON Web Encryption is invalid.',
        );
      });

      it('should unwrap the provided Encrypted Key.', async () => {
        const unwrapSpy = jest.spyOn(backend['aeskwBackend'], 'unwrap');
        await expect(backend.unwrap(ek, jwk, header)).resolves.toStrictEqual(cek);
        expect(unwrapSpy).toHaveBeenCalledOnce();
      });
    });

    describe('generateContentEncryptionKey()', () => {
      it('should throw when the provided JSON Web Key Parameter "alg" does not match the JSON Web Encryption Algorithm.', async () => {
        await expect(backend.generateContentEncryptionKey(wrongAlgJwk, header)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The provided JSON Web Key cannot be used by the JSON Web Encryption Algorithm.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "kty" does not match the required JSON Web Key Key Type.', async () => {
        await expect(backend.generateContentEncryptionKey(<any>wrongKtyJwk, header)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Encryption Algorithm only accepts "oct" JSON Web Keys.',
        );
      });

      it('should generate a Content Encryption Key.', async () => {
        await expect(backend.generateContentEncryptionKey(jwk, header)).resolves.toStrictEqual(cek);
      });
    });
  });

  describe('PBES2-HS512+A256KW', () => {
    const backend = new PBES2JsonWebEncryptionKeyManagementBackend('PBES2-HS512+A256KW');

    const ek = Buffer.from('T0eFFwZwsNPWK0y1j6TUd-EbvYGAq6uLtFKuhO3_eGsstZ4Uq3L8XQ', 'base64url');

    let header: JsonWebEncryptionHeader<PBES2JsonWebEncryptionKeyManagementHeaderParameters>;

    const wrongJwk = new OctetSequenceJsonWebKey({
      kty: 'oct',
      k: Buffer.from('Bad password.', 'utf8').toString('base64url'),
    });

    const wrongP2SHeader = new JsonWebEncryptionHeader<PBES2JsonWebEncryptionKeyManagementHeaderParameters>({
      alg: 'PBES2-HS512+A256KW',
      enc: 'A128CBC-HS256',
      p2s: 'QpGYnmJUuIdGFzIzaiEvJw',
      p2c: 4096,
    });

    const wrongP2CHeader = new JsonWebEncryptionHeader<PBES2JsonWebEncryptionKeyManagementHeaderParameters>({
      alg: 'PBES2-HS512+A256KW',
      enc: 'A128CBC-HS256',
      p2s: '2WCTcJZ1Rvd_CJuJripQ1w',
      p2c: 8192,
    });

    beforeEach(() => {
      header = new JsonWebEncryptionHeader<PBES2JsonWebEncryptionKeyManagementHeaderParameters>({
        alg: 'PBES2-HS512+A256KW',
        enc: 'A128CBC-HS256',
        p2s: '2WCTcJZ1Rvd_CJuJripQ1w',
        p2c: 4096,
      });
    });

    describe('constructor', () => {
      it('should have a 256-bit AES Key Wrap JSON Web Encryption Key Management Backend.', () => {
        expect(backend['aeskwBackend']).toBeInstanceOf(AESKWJsonWebEncryptionKeyManagementBackend);
        expect(backend['aeskwBackend']!['algorithm']).toBe<KeyManagementAlgorithm>('A256KW');
      });
    });

    describe('wrap()', () => {
      it('should throw when the provided JSON Web Key Parameter "alg" does not match the JSON Web Encryption Algorithm.', async () => {
        await expect(backend.wrap(cek, wrongAlgJwk, header)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The provided JSON Web Key cannot be used by the JSON Web Encryption Algorithm.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "kty" does not match the required JSON Web Key Key Type.', async () => {
        await expect(backend.wrap(cek, <any>wrongKtyJwk, header)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Encryption Algorithm only accepts "oct" JSON Web Keys.',
        );
      });

      it.each(invalidP2Ss)('should throw when the provided JOSE Header Parameter "p2s" is invalid.', async (p2s) => {
        Reflect.set(header.parameters, 'p2s', p2s);

        await expect(backend.wrap(cek, jwk, header)).rejects.toThrowWithMessage(
          InvalidJoseHeaderError,
          'Invalid JOSE Header Parameter "p2s".',
        );
      });

      it.each(invalidP2Cs)('should throw when the provided JOSE Header Parameter "p2c" is invalid.', async (p2c) => {
        Reflect.set(header.parameters, 'p2c', p2c);

        await expect(backend.wrap(cek, jwk, header)).rejects.toThrowWithMessage(
          InvalidJoseHeaderError,
          'Invalid JOSE Header Parameter "p2c".',
        );
      });

      it('should wrap the provided Content Encryption Key.', async () => {
        const wrapSpy = jest.spyOn(backend['aeskwBackend'], 'wrap');
        await expect(backend.wrap(cek, jwk, header)).resolves.toStrictEqual(ek);
        expect(wrapSpy).toHaveBeenCalledOnce();
      });
    });

    describe('unwrap()', () => {
      it('should throw when the provided JSON Web Key Parameter "alg" does not match the JSON Web Encryption Algorithm.', async () => {
        await expect(backend.unwrap(ek, wrongAlgJwk, header)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The provided JSON Web Key cannot be used by the JSON Web Encryption Algorithm.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "kty" does not match the required JSON Web Key Key Type.', async () => {
        await expect(backend.unwrap(ek, <any>wrongKtyJwk, header)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Encryption Algorithm only accepts "oct" JSON Web Keys.',
        );
      });

      it.each(invalidP2Ss)('should throw when the provided JOSE Header Parameter "p2s" is invalid.', async (p2s) => {
        Reflect.set(header.parameters, 'p2s', p2s);

        await expect(backend.unwrap(ek, jwk, header)).rejects.toThrowWithMessage(
          InvalidJoseHeaderError,
          'Invalid JOSE Header Parameter "p2s".',
        );
      });

      it.each(invalidP2Cs)('should throw when the provided JOSE Header Parameter "p2c" is invalid.', async (p2c) => {
        Reflect.set(header.parameters, 'p2c', p2c);

        await expect(backend.unwrap(ek, jwk, header)).rejects.toThrowWithMessage(
          InvalidJoseHeaderError,
          'Invalid JOSE Header Parameter "p2c".',
        );
      });

      it('should throw when the provided Encrypted Key is invalid.', async () => {
        await expect(backend.unwrap(wrongEk, jwk, header)).rejects.toThrowWithMessage(
          InvalidJsonWebEncryptionError,
          'The provided JSON Web Encryption is invalid.',
        );
      });

      it('should throw when the provided JSON Web Key is invalid.', async () => {
        await expect(backend.unwrap(ek, wrongJwk, header)).rejects.toThrowWithMessage(
          InvalidJsonWebEncryptionError,
          'The provided JSON Web Encryption is invalid.',
        );
      });

      it('should throw when providing the wrong JSON Web Encryption Header Parameter "iv".', async () => {
        await expect(backend.unwrap(ek, jwk, wrongP2SHeader)).rejects.toThrowWithMessage(
          InvalidJsonWebEncryptionError,
          'The provided JSON Web Encryption is invalid.',
        );
      });

      it('should throw when providing the wrong JSON Web Encryption Header Parameter "tag".', async () => {
        await expect(backend.unwrap(ek, jwk, wrongP2CHeader)).rejects.toThrowWithMessage(
          InvalidJsonWebEncryptionError,
          'The provided JSON Web Encryption is invalid.',
        );
      });

      it('should unwrap the provided Encrypted Key.', async () => {
        const unwrapSpy = jest.spyOn(backend['aeskwBackend'], 'unwrap');
        await expect(backend.unwrap(ek, jwk, header)).resolves.toStrictEqual(cek);
        expect(unwrapSpy).toHaveBeenCalledOnce();
      });
    });

    describe('generateContentEncryptionKey()', () => {
      it('should throw when the provided JSON Web Key Parameter "alg" does not match the JSON Web Encryption Algorithm.', async () => {
        await expect(backend.generateContentEncryptionKey(wrongAlgJwk, header)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The provided JSON Web Key cannot be used by the JSON Web Encryption Algorithm.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "kty" does not match the required JSON Web Key Key Type.', async () => {
        await expect(backend.generateContentEncryptionKey(<any>wrongKtyJwk, header)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Encryption Algorithm only accepts "oct" JSON Web Keys.',
        );
      });

      it('should generate a Content Encryption Key.', async () => {
        await expect(backend.generateContentEncryptionKey(jwk, header)).resolves.toStrictEqual(cek);
      });
    });
  });
});
