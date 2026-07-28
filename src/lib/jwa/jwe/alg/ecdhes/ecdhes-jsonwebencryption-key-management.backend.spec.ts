import { Buffer } from 'buffer';
import crypto from 'crypto';

import { InvalidJoseHeaderError } from '../../../../errors/invalid-jose-header.error';
import { InvalidJsonWebKeyError } from '../../../../errors/invalid-jsonwebkey.error';
import { JsonWebEncryptionHeader } from '../../../../jwe/jsonwebencryption-header';
import { EllipticCurveJsonWebKey } from '../../../jwk/ec/elliptic-curve.jsonwebkey';
import { EllipticCurveJsonWebKeyParameters } from '../../../jwk/ec/elliptic-curve-jsonwebkey.parameters';
import { OctetKeyPairJsonWebKey } from '../../../jwk/okp/octet-key-pair.jsonwebkey';
import { OctetKeyPairJsonWebKeyParameters } from '../../../jwk/okp/octet-key-pair-jsonwebkey.parameters';
import { RsaJsonWebKey } from '../../../jwk/rsa/rsa.jsonwebkey';
import { AESKWJsonWebEncryptionKeyManagementBackend } from '../aeskw/aeskw-jsonwebencryption-key-management.backend';
import { KeyManagementAlgorithm } from '../key-management-algorithm.type';
import { ECDHESJsonWebEncryptionKeyManagementBackend } from './ecdhes-jsonwebencryption-key-management.backend';
import { ECDHESJsonWebEncryptionKeyManagementHeaderParameters } from './ecdhes-jsonwebencryption-key-management-header.parameters';

jest.mock<typeof crypto>('crypto', () => ({
  ...jest.requireActual('crypto'),
  randomBytes: jest.fn().mockImplementation((size, cb) => cb(null, Buffer.from([...Array(size).keys()]))),
}));

const aliceJwk = new EllipticCurveJsonWebKey({
  kty: 'EC',
  crv: 'P-256',
  x: 'gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0',
  y: 'SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps',
  d: '0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo',
});

const bobJwk = new EllipticCurveJsonWebKey({
  kty: 'EC',
  crv: 'P-256',
  x: 'weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ',
  y: 'e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck',
  d: 'VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw',
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

const wrongCrvJwk = new OctetKeyPairJsonWebKey({
  kty: 'OKP',
  crv: 'Ed25519',
  x: 'g5p3LK1Mpb1lFnBDRlwvZPZSOnbGFSKnyngC7AOAsgE',
  d: 'S52ag71xVm7aw2EQA2TWAJGsLKAecKVz2oJJVyK9FPA',
});

const invalidEpks: any[] = [
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
  [],
  {},
  { kty: 'a' },
  aliceJwk.parameters,
  { ...aliceJwk.toJSON(), alg: 'unknown' },
  { ...aliceJwk.toJSON(), alg: 'ES256' },
  wrongKtyJwk.parameters,
  wrongCrvJwk.parameters,
];

const invalidApus: any[] = [
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

const invalidApvs: any[] = [
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

describe('ECDH-ES JSON Web Encryption Key Management Backend', () => {
  const wrongAlgJwk = new EllipticCurveJsonWebKey({
    ...bobJwk.parameters,
    alg: 'ES256',
  });

  const wrongJwk = new EllipticCurveJsonWebKey({
    kty: 'EC',
    crv: 'P-384',
    x: 'WQHUcjVyE63vMl-SJNYYmqgYkJKkNGOctFcD368nyI2DogjP-34teV5KUZo82AxT',
    y: 'T4hHQx5WkQxjInUkQ1mMBu9iOw_ICOC5wh8QP79BRi-UPYfMP0z7b-LODdijwwFb',
    d: 'Sp2paYMyI8y4oWP7GfQXaSyaoFjyd-9IvqnQlAWAdYg_z-45Q809-_kgR47c15X2',
  });

  beforeEach(() => {
    jest.restoreAllMocks();
  });

  describe('ECDH-ES', () => {
    const backend = new ECDHESJsonWebEncryptionKeyManagementBackend('ECDH-ES');

    const cek128Bits = Buffer.from('u5erXQ6FbY-PwD4mWyQqfQ', 'base64url');
    const cek192Bits = Buffer.from('jwOAN1qz_5uOTrKU91yJ_HuH_t4dWJQd', 'base64url');
    const cek256Bits = Buffer.from('sn4a5FuGA19w_9WEuHo1U71fFW7At1TNTQ909lYtNTU', 'base64url');
    const apuCek128Bits = Buffer.from('fbe48nuDSWsjX7kNqhQNDw', 'base64url');
    const apuCek192Bits = Buffer.from('VjXA7xvikgMVBTGyN2UrXmr6DQDGpMwL', 'base64url');
    const apuCek256Bits = Buffer.from('pE9Ty3o4pTtE6XqB_17sQhGnZQqjIX7v1pYuuAaEhKk', 'base64url');
    const apvCek128Bits = Buffer.from('6vQWSAsXa-gHPFXtodR62g', 'base64url');
    const apvCek192Bits = Buffer.from('rk4VZ0C3r_CXfVYzwsAxEGJh_aLa2tBx', 'base64url');
    const apvCek256Bits = Buffer.from('TOgs8CkQRcAuhE6_8dtHPsmLIA_c1Kot9ewZWKrppqc', 'base64url');
    const apuAndApvCek128Bits = Buffer.from('VqqN6vgjbSBcIijNcacQGg', 'base64url');
    const apuAndApvCek192Bits = Buffer.from('7lHSXT1M424WRVgI9WY0gf_ldevLI9Gx', 'base64url');
    const apuAndApvCek256Bits = Buffer.from('_VpjYu4u855R2KndssmFBzkLWo9qO8FK9HxH0bWOO2A', 'base64url');

    const ek = Buffer.alloc(0);

    let header: JsonWebEncryptionHeader<ECDHESJsonWebEncryptionKeyManagementHeaderParameters>;

    const sameApuApvHeader = new JsonWebEncryptionHeader<ECDHESJsonWebEncryptionKeyManagementHeaderParameters>({
      alg: 'ECDH-ES',
      enc: 'A128GCM',
      apu: 'Qm9i',
      apv: 'Qm9i',
      epk: aliceJwk.toJSON() as EllipticCurveJsonWebKeyParameters | OctetKeyPairJsonWebKeyParameters,
    });

    const cek128BitsHeader = new JsonWebEncryptionHeader<ECDHESJsonWebEncryptionKeyManagementHeaderParameters>({
      alg: 'ECDH-ES',
      enc: 'A128GCM',
      epk: aliceJwk.toJSON() as EllipticCurveJsonWebKeyParameters | OctetKeyPairJsonWebKeyParameters,
    });

    const cek192BitsHeader = new JsonWebEncryptionHeader<ECDHESJsonWebEncryptionKeyManagementHeaderParameters>({
      alg: 'ECDH-ES',
      enc: 'A192GCM',
      epk: aliceJwk.toJSON() as EllipticCurveJsonWebKeyParameters | OctetKeyPairJsonWebKeyParameters,
    });

    const cek256BitsHeader = new JsonWebEncryptionHeader<ECDHESJsonWebEncryptionKeyManagementHeaderParameters>({
      alg: 'ECDH-ES',
      enc: 'A256GCM',
      epk: aliceJwk.toJSON() as EllipticCurveJsonWebKeyParameters | OctetKeyPairJsonWebKeyParameters,
    });

    const apuCek128BitsHeader = new JsonWebEncryptionHeader<ECDHESJsonWebEncryptionKeyManagementHeaderParameters>({
      alg: 'ECDH-ES',
      enc: 'A128GCM',
      apu: 'QWxpY2U',
      epk: aliceJwk.toJSON() as EllipticCurveJsonWebKeyParameters | OctetKeyPairJsonWebKeyParameters,
    });

    const apuCek192BitsHeader = new JsonWebEncryptionHeader<ECDHESJsonWebEncryptionKeyManagementHeaderParameters>({
      alg: 'ECDH-ES',
      enc: 'A192GCM',
      apu: 'QWxpY2U',
      epk: aliceJwk.toJSON() as EllipticCurveJsonWebKeyParameters | OctetKeyPairJsonWebKeyParameters,
    });

    const apuCek256BitsHeader = new JsonWebEncryptionHeader<ECDHESJsonWebEncryptionKeyManagementHeaderParameters>({
      alg: 'ECDH-ES',
      enc: 'A256GCM',
      apu: 'QWxpY2U',
      epk: aliceJwk.toJSON() as EllipticCurveJsonWebKeyParameters | OctetKeyPairJsonWebKeyParameters,
    });

    const apvCek128BitsHeader = new JsonWebEncryptionHeader<ECDHESJsonWebEncryptionKeyManagementHeaderParameters>({
      alg: 'ECDH-ES',
      enc: 'A128GCM',
      apv: 'Qm9i',
      epk: aliceJwk.toJSON() as EllipticCurveJsonWebKeyParameters | OctetKeyPairJsonWebKeyParameters,
    });

    const apvCek192BitsHeader = new JsonWebEncryptionHeader<ECDHESJsonWebEncryptionKeyManagementHeaderParameters>({
      alg: 'ECDH-ES',
      enc: 'A192GCM',
      apv: 'Qm9i',
      epk: aliceJwk.toJSON() as EllipticCurveJsonWebKeyParameters | OctetKeyPairJsonWebKeyParameters,
    });

    const apvCek256BitsHeader = new JsonWebEncryptionHeader<ECDHESJsonWebEncryptionKeyManagementHeaderParameters>({
      alg: 'ECDH-ES',
      enc: 'A256GCM',
      apv: 'Qm9i',
      epk: aliceJwk.toJSON() as EllipticCurveJsonWebKeyParameters | OctetKeyPairJsonWebKeyParameters,
    });

    const apuAndApvCek128BitsHeader = new JsonWebEncryptionHeader<ECDHESJsonWebEncryptionKeyManagementHeaderParameters>(
      {
        alg: 'ECDH-ES',
        enc: 'A128GCM',
        apu: 'QWxpY2U',
        apv: 'Qm9i',
        epk: aliceJwk.toJSON() as EllipticCurveJsonWebKeyParameters | OctetKeyPairJsonWebKeyParameters,
      },
    );

    const apuAndApvCek192BitsHeader = new JsonWebEncryptionHeader<ECDHESJsonWebEncryptionKeyManagementHeaderParameters>(
      {
        alg: 'ECDH-ES',
        enc: 'A192GCM',
        apu: 'QWxpY2U',
        apv: 'Qm9i',
        epk: aliceJwk.toJSON() as EllipticCurveJsonWebKeyParameters | OctetKeyPairJsonWebKeyParameters,
      },
    );

    const apuAndApvCek256BitsHeader = new JsonWebEncryptionHeader<ECDHESJsonWebEncryptionKeyManagementHeaderParameters>(
      {
        alg: 'ECDH-ES',
        enc: 'A256GCM',
        apu: 'QWxpY2U',
        apv: 'Qm9i',
        epk: aliceJwk.toJSON() as EllipticCurveJsonWebKeyParameters | OctetKeyPairJsonWebKeyParameters,
      },
    );

    beforeEach(() => {
      header = new JsonWebEncryptionHeader<ECDHESJsonWebEncryptionKeyManagementHeaderParameters>({
        alg: 'ECDH-ES',
        enc: 'A128GCM',
        apu: 'QWxpY2U',
        apv: 'Qm9i',
        epk: aliceJwk.toJSON() as EllipticCurveJsonWebKeyParameters | OctetKeyPairJsonWebKeyParameters,
      });
    });

    describe('constructor', () => {
      it('should have an undefined AES Key Wrap JSON Web Encryption Key Management Backend.', () => {
        expect(backend['aeskwBackend']).toBeUndefined();
      });
    });

    describe('wrap()', () => {
      it('should throw when the provided JSON Web Key Parameter "alg" does not match the JSON Web Encryption Algorithm.', async () => {
        await expect(backend.wrap(cek128Bits, wrongAlgJwk, header)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The provided JSON Web Key cannot be used by the JSON Web Encryption Algorithm.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "kty" does not match the required JSON Web Key Key Type.', async () => {
        await expect(backend.wrap(cek128Bits, <any>wrongKtyJwk, header)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Encryption Algorithm only accepts "EC" and "OKP" JSON Web Keys.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "crv" does not match the required JSON Web Key Curve.', async () => {
        await expect(backend.wrap(cek128Bits, wrongCrvJwk, header)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Key Parameter "crv" must be "P-256", "P-384", "P-521", "X25519", "X448" or "secp256k1".',
        );
      });

      it.each(invalidEpks)('should throw when the provided JOSE Header Parameter "epk" is invalid.', async (epk) => {
        Reflect.set(header.parameters, 'epk', epk);

        await expect(backend.wrap(cek128Bits, bobJwk, header)).rejects.toThrowWithMessage(
          InvalidJoseHeaderError,
          'Invalid JOSE Header Parameter "epk".',
        );
      });

      it.each(invalidApus)('should throw when the provided JOSE Header Parameter "apu" is invalid.', async (apu) => {
        Reflect.set(header.parameters, 'apu', apu);

        await expect(backend.wrap(cek128Bits, bobJwk, header)).rejects.toThrowWithMessage(
          InvalidJoseHeaderError,
          'Invalid JOSE Header Parameter "apu".',
        );
      });

      it.each(invalidApvs)('should throw when the provided JOSE Header Parameter "apv" is invalid.', async (apv) => {
        Reflect.set(header.parameters, 'apv', apv);

        await expect(backend.wrap(cek128Bits, bobJwk, header)).rejects.toThrowWithMessage(
          InvalidJoseHeaderError,
          'Invalid JOSE Header Parameter "apv".',
        );
      });

      it('should throw when the provided JOSE Header Parameters "apu" and "apv" are equal.', async () => {
        await expect(backend.wrap(cek128Bits, bobJwk, sameApuApvHeader)).rejects.toThrowWithMessage(
          InvalidJoseHeaderError,
          'The JOSE Header Parameters "apu" and "apv" cannot be equal.',
        );
      });

      it('should return an empty buffer as the Encrypted Key of the 128 bits Content Encryption Key.', async () => {
        await expect(backend.wrap(cek128Bits, bobJwk, cek128BitsHeader)).resolves.toStrictEqual(ek);
      });

      it('should return an empty buffer as the Encrypted Key of the 192 bits Content Encryption Key.', async () => {
        await expect(backend.wrap(cek192Bits, bobJwk, cek192BitsHeader)).resolves.toStrictEqual(ek);
      });

      it('should return an empty buffer as the Encrypted Key of the 256 bits Content Encryption Key.', async () => {
        await expect(backend.wrap(cek256Bits, bobJwk, cek256BitsHeader)).resolves.toStrictEqual(ek);
      });

      it('should return an empty buffer as the Encrypted Key of the 128 bits Content Encryption Key with "apu".', async () => {
        await expect(backend.wrap(apuCek128Bits, bobJwk, apuCek128BitsHeader)).resolves.toStrictEqual(ek);
      });

      it('should return an empty buffer as the Encrypted Key of the 192 bits Content Encryption Key with "apu".', async () => {
        await expect(backend.wrap(apuCek192Bits, bobJwk, apuCek192BitsHeader)).resolves.toStrictEqual(ek);
      });

      it('should return an empty buffer as the Encrypted Key of the 256 bits Content Encryption Key with "apu".', async () => {
        await expect(backend.wrap(apuCek256Bits, bobJwk, apuCek256BitsHeader)).resolves.toStrictEqual(ek);
      });

      it('should return an empty buffer as the Encrypted Key of the 128 bits Content Encryption Key with "apv".', async () => {
        await expect(backend.wrap(apvCek128Bits, bobJwk, apvCek128BitsHeader)).resolves.toStrictEqual(ek);
      });

      it('should return an empty buffer as the Encrypted Key of the 192 bits Content Encryption Key with "apv".', async () => {
        await expect(backend.wrap(apvCek192Bits, bobJwk, apvCek192BitsHeader)).resolves.toStrictEqual(ek);
      });

      it('should return an empty buffer as the Encrypted Key of the 256 bits Content Encryption Key with "apv".', async () => {
        await expect(backend.wrap(apvCek256Bits, bobJwk, apvCek256BitsHeader)).resolves.toStrictEqual(ek);
      });

      it('should return an empty buffer as the Encrypted Key of the 128 bits Content Encryption Key with "apu" and "apv".', async () => {
        await expect(backend.wrap(apuAndApvCek128Bits, bobJwk, apuAndApvCek128BitsHeader)).resolves.toStrictEqual(ek);
      });

      it('should return an empty buffer as the Encrypted Key of the 192 bits Content Encryption Key with "apu" and "apv".', async () => {
        await expect(backend.wrap(apuAndApvCek192Bits, bobJwk, apuAndApvCek192BitsHeader)).resolves.toStrictEqual(ek);
      });

      it('should return an empty buffer as the Encrypted Key of the 256 bits Content Encryption Key with "apu" and "apv".', async () => {
        await expect(backend.wrap(apuAndApvCek256Bits, bobJwk, apuAndApvCek256BitsHeader)).resolves.toStrictEqual(ek);
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
          'The JSON Web Encryption Algorithm only accepts "EC" and "OKP" JSON Web Keys.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "crv" does not match the required JSON Web Key Curve.', async () => {
        await expect(backend.unwrap(ek, wrongCrvJwk, header)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Key Parameter "crv" must be "P-256", "P-384", "P-521", "X25519", "X448" or "secp256k1".',
        );
      });

      it.each(invalidEpks)('should throw when the provided JOSE Header Parameter "epk" is invalid.', async (epk) => {
        Reflect.set(header.parameters, 'epk', epk);

        await expect(backend.unwrap(ek, bobJwk, header)).rejects.toThrowWithMessage(
          InvalidJoseHeaderError,
          'Invalid JOSE Header Parameter "epk".',
        );
      });

      it.each(invalidApus)('should throw when the provided JOSE Header Parameter "apu" is invalid.', async (apu) => {
        Reflect.set(header.parameters, 'apu', apu);

        await expect(backend.unwrap(ek, bobJwk, header)).rejects.toThrowWithMessage(
          InvalidJoseHeaderError,
          'Invalid JOSE Header Parameter "apu".',
        );
      });

      it.each(invalidApvs)('should throw when the provided JOSE Header Parameter "apv" is invalid.', async (apv) => {
        Reflect.set(header.parameters, 'apv', apv);

        await expect(backend.unwrap(ek, bobJwk, header)).rejects.toThrowWithMessage(
          InvalidJoseHeaderError,
          'Invalid JOSE Header Parameter "apv".',
        );
      });

      it('should throw when the provided JOSE Header Parameters "apu" and "apv" are equal.', async () => {
        await expect(backend.unwrap(ek, bobJwk, sameApuApvHeader)).rejects.toThrowWithMessage(
          InvalidJoseHeaderError,
          'The JOSE Header Parameters "apu" and "apv" cannot be equal.',
        );
      });

      it('should throw when the provided JOSE Header Parameter "epk" and the provided Unwrap JSON Web Key have different Curves.', async () => {
        await expect(backend.unwrap(ek, wrongJwk, header)).rejects.toThrowWithMessage(
          InvalidJoseHeaderError,
          'Invalid JOSE Header Parameter "epk".',
        );
      });

      it('should return the Shared Secret as the 128 bits Content Encryption Key.', async () => {
        await expect(backend.unwrap(ek, bobJwk, cek128BitsHeader)).resolves.toStrictEqual(cek128Bits);
      });

      it('should return the Shared Secret as the 192 bits Content Encryption Key.', async () => {
        await expect(backend.unwrap(ek, bobJwk, cek192BitsHeader)).resolves.toStrictEqual(cek192Bits);
      });

      it('should return the Shared Secret as the 256 bits Content Encryption Key.', async () => {
        await expect(backend.unwrap(ek, bobJwk, cek256BitsHeader)).resolves.toStrictEqual(cek256Bits);
      });

      it('should return the Shared Secret as the 128 bits Content Encryption Key with "apu".', async () => {
        await expect(backend.unwrap(ek, bobJwk, apuCek128BitsHeader)).resolves.toStrictEqual(apuCek128Bits);
      });

      it('should return the Shared Secret as the 192 bits Content Encryption Key with "apu".', async () => {
        await expect(backend.unwrap(ek, bobJwk, apuCek192BitsHeader)).resolves.toStrictEqual(apuCek192Bits);
      });

      it('should return the Shared Secret as the 256 bits Content Encryption Key with "apu".', async () => {
        await expect(backend.unwrap(ek, bobJwk, apuCek256BitsHeader)).resolves.toStrictEqual(apuCek256Bits);
      });

      it('should return the Shared Secret as the 128 bits Content Encryption Key with "apv".', async () => {
        await expect(backend.unwrap(ek, bobJwk, apvCek128BitsHeader)).resolves.toStrictEqual(apvCek128Bits);
      });

      it('should return the Shared Secret as the 192 bits Content Encryption Key with "apv".', async () => {
        await expect(backend.unwrap(ek, bobJwk, apvCek192BitsHeader)).resolves.toStrictEqual(apvCek192Bits);
      });

      it('should return the Shared Secret as the 256 bits Content Encryption Key with "apv".', async () => {
        await expect(backend.unwrap(ek, bobJwk, apvCek256BitsHeader)).resolves.toStrictEqual(apvCek256Bits);
      });

      it('should return the Shared Secret as the 128 bits Content Encryption Key with "apu" and "apv".', async () => {
        await expect(backend.unwrap(ek, bobJwk, apuAndApvCek128BitsHeader)).resolves.toStrictEqual(apuAndApvCek128Bits);
      });

      it('should return the Shared Secret as the 192 bits Content Encryption Key with "apu" and "apv".', async () => {
        await expect(backend.unwrap(ek, bobJwk, apuAndApvCek192BitsHeader)).resolves.toStrictEqual(apuAndApvCek192Bits);
      });

      it('should return the Shared Secret as the 256 bits Content Encryption Key with "apu" and "apv".', async () => {
        await expect(backend.unwrap(ek, bobJwk, apuAndApvCek256BitsHeader)).resolves.toStrictEqual(apuAndApvCek256Bits);
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
          'The JSON Web Encryption Algorithm only accepts "EC" and "OKP" JSON Web Keys.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "crv" does not match the required JSON Web Key Curve.', async () => {
        await expect(backend.generateContentEncryptionKey(wrongCrvJwk, header)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Key Parameter "crv" must be "P-256", "P-384", "P-521", "X25519", "X448" or "secp256k1".',
        );
      });

      it.each(invalidEpks)('should throw when the provided JOSE Header Parameter "epk" is invalid.', async (epk) => {
        Reflect.set(header.parameters, 'epk', epk);

        await expect(backend.generateContentEncryptionKey(bobJwk, header)).rejects.toThrowWithMessage(
          InvalidJoseHeaderError,
          'Invalid JOSE Header Parameter "epk".',
        );
      });

      it.each(invalidApus)('should throw when the provided JOSE Header Parameter "apu" is invalid.', async (apu) => {
        Reflect.set(header.parameters, 'apu', apu);

        await expect(backend.generateContentEncryptionKey(bobJwk, header)).rejects.toThrowWithMessage(
          InvalidJoseHeaderError,
          'Invalid JOSE Header Parameter "apu".',
        );
      });

      it.each(invalidApvs)('should throw when the provided JOSE Header Parameter "apv" is invalid.', async (apv) => {
        Reflect.set(header.parameters, 'apv', apv);

        await expect(backend.generateContentEncryptionKey(bobJwk, header)).rejects.toThrowWithMessage(
          InvalidJoseHeaderError,
          'Invalid JOSE Header Parameter "apv".',
        );
      });

      it('should throw when the provided JOSE Header Parameters "apu" and "apv" are equal.', async () => {
        await expect(backend.generateContentEncryptionKey(bobJwk, sameApuApvHeader)).rejects.toThrowWithMessage(
          InvalidJoseHeaderError,
          'The JOSE Header Parameters "apu" and "apv" cannot be equal.',
        );
      });

      it('should throw when the provided JOSE Header Parameter "epk" and the provided Unwrap JSON Web Key have different Curves.', async () => {
        await expect(backend.generateContentEncryptionKey(wrongJwk, header)).rejects.toThrowWithMessage(
          InvalidJoseHeaderError,
          'Invalid JOSE Header Parameter "epk".',
        );
      });

      it('should return the Shared Secret as the 128 bits Content Encryption Key.', async () => {
        await expect(backend.generateContentEncryptionKey(bobJwk, cek128BitsHeader)).resolves.toStrictEqual(cek128Bits);
      });

      it('should return the Shared Secret as the 192 bits Content Encryption Key.', async () => {
        await expect(backend.generateContentEncryptionKey(bobJwk, cek192BitsHeader)).resolves.toStrictEqual(cek192Bits);
      });

      it('should return the Shared Secret as the 256 bits Content Encryption Key.', async () => {
        await expect(backend.generateContentEncryptionKey(bobJwk, cek256BitsHeader)).resolves.toStrictEqual(cek256Bits);
      });

      it('should return the Shared Secret as the 128 bits Content Encryption Key with "apu".', async () => {
        await expect(backend.generateContentEncryptionKey(bobJwk, apuCek128BitsHeader)).resolves.toStrictEqual(
          apuCek128Bits,
        );
      });

      it('should return the Shared Secret as the 192 bits Content Encryption Key with "apu".', async () => {
        await expect(backend.generateContentEncryptionKey(bobJwk, apuCek192BitsHeader)).resolves.toStrictEqual(
          apuCek192Bits,
        );
      });

      it('should return the Shared Secret as the 256 bits Content Encryption Key with "apu".', async () => {
        await expect(backend.generateContentEncryptionKey(bobJwk, apuCek256BitsHeader)).resolves.toStrictEqual(
          apuCek256Bits,
        );
      });

      it('should return the Shared Secret as the 128 bits Content Encryption Key with "apv".', async () => {
        await expect(backend.generateContentEncryptionKey(bobJwk, apvCek128BitsHeader)).resolves.toStrictEqual(
          apvCek128Bits,
        );
      });

      it('should return the Shared Secret as the 192 bits Content Encryption Key with "apv".', async () => {
        await expect(backend.generateContentEncryptionKey(bobJwk, apvCek192BitsHeader)).resolves.toStrictEqual(
          apvCek192Bits,
        );
      });

      it('should return the Shared Secret as the 256 bits Content Encryption Key with "apv".', async () => {
        await expect(backend.generateContentEncryptionKey(bobJwk, apvCek256BitsHeader)).resolves.toStrictEqual(
          apvCek256Bits,
        );
      });

      it('should return the Shared Secret as the 128 bits Content Encryption Key with "apu" and "apv".', async () => {
        await expect(backend.generateContentEncryptionKey(bobJwk, apuAndApvCek128BitsHeader)).resolves.toStrictEqual(
          apuAndApvCek128Bits,
        );
      });

      it('should return the Shared Secret as the 192 bits Content Encryption Key with "apu" and "apv".', async () => {
        await expect(backend.generateContentEncryptionKey(bobJwk, apuAndApvCek192BitsHeader)).resolves.toStrictEqual(
          apuAndApvCek192Bits,
        );
      });

      it('should return the Shared Secret as the 256 bits Content Encryption Key with "apu" and "apv".', async () => {
        await expect(backend.generateContentEncryptionKey(bobJwk, apuAndApvCek256BitsHeader)).resolves.toStrictEqual(
          apuAndApvCek256Bits,
        );
      });
    });
  });

  describe('ECDH-ES+A128KW', () => {
    const backend = new ECDHESJsonWebEncryptionKeyManagementBackend('ECDH-ES+A128KW');

    const cek = Buffer.from('AAECAwQFBgcICQoLDA0ODw', 'base64url');

    const ek = Buffer.from('ebJEv4Jb76ZKe0XgbShUPWRPbGCUZetC', 'base64url');
    const apuEk = Buffer.from('jlEAlsw3BryImiRLd-anLh0GJuqC0RdL', 'base64url');
    const apvEk = Buffer.from('bewUAshl5uzADF38Cbl-imgA9FWoj-l7', 'base64url');
    const apuAndApvEk = Buffer.from('-O-0N512N8f1bIHeDte0fJLO1u2knyk2', 'base64url');

    let header: JsonWebEncryptionHeader<ECDHESJsonWebEncryptionKeyManagementHeaderParameters>;

    const sameApuApvHeader = new JsonWebEncryptionHeader<ECDHESJsonWebEncryptionKeyManagementHeaderParameters>({
      alg: 'ECDH-ES+A128KW',
      enc: 'A128GCM',
      apu: 'Qm9i',
      apv: 'Qm9i',
      epk: aliceJwk.toJSON() as EllipticCurveJsonWebKeyParameters | OctetKeyPairJsonWebKeyParameters,
    });

    const ekHeader = new JsonWebEncryptionHeader<ECDHESJsonWebEncryptionKeyManagementHeaderParameters>({
      alg: 'ECDH-ES',
      enc: 'A128GCM',
      epk: aliceJwk.toJSON() as EllipticCurveJsonWebKeyParameters | OctetKeyPairJsonWebKeyParameters,
    });

    const apuEkHeader = new JsonWebEncryptionHeader<ECDHESJsonWebEncryptionKeyManagementHeaderParameters>({
      alg: 'ECDH-ES',
      enc: 'A128GCM',
      apu: 'QWxpY2U',
      epk: aliceJwk.toJSON() as EllipticCurveJsonWebKeyParameters | OctetKeyPairJsonWebKeyParameters,
    });

    const apvEkHeader = new JsonWebEncryptionHeader<ECDHESJsonWebEncryptionKeyManagementHeaderParameters>({
      alg: 'ECDH-ES',
      enc: 'A128GCM',
      apv: 'Qm9i',
      epk: aliceJwk.toJSON() as EllipticCurveJsonWebKeyParameters | OctetKeyPairJsonWebKeyParameters,
    });

    const apuAndApvEkHeader = new JsonWebEncryptionHeader<ECDHESJsonWebEncryptionKeyManagementHeaderParameters>({
      alg: 'ECDH-ES',
      enc: 'A128GCM',
      apu: 'QWxpY2U',
      apv: 'Qm9i',
      epk: aliceJwk.toJSON() as EllipticCurveJsonWebKeyParameters | OctetKeyPairJsonWebKeyParameters,
    });

    beforeEach(() => {
      header = new JsonWebEncryptionHeader<ECDHESJsonWebEncryptionKeyManagementHeaderParameters>({
        alg: 'ECDH-ES+A128KW',
        enc: 'A128GCM',
        apu: 'QWxpY2U',
        apv: 'Qm9i',
        epk: aliceJwk.toJSON() as EllipticCurveJsonWebKeyParameters | OctetKeyPairJsonWebKeyParameters,
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
          'The JSON Web Encryption Algorithm only accepts "EC" and "OKP" JSON Web Keys.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "crv" does not match the required JSON Web Key Curve.', async () => {
        await expect(backend.wrap(cek, wrongCrvJwk, header)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Key Parameter "crv" must be "P-256", "P-384", "P-521", "X25519", "X448" or "secp256k1".',
        );
      });

      it.each(invalidEpks)('should throw when the provided JOSE Header Parameter "epk" is invalid.', async (epk) => {
        Reflect.set(header.parameters, 'epk', epk);

        await expect(backend.wrap(cek, bobJwk, header)).rejects.toThrowWithMessage(
          InvalidJoseHeaderError,
          'Invalid JOSE Header Parameter "epk".',
        );
      });

      it.each(invalidApus)('should throw when the provided JOSE Header Parameter "apu" is invalid.', async (apu) => {
        Reflect.set(header.parameters, 'apu', apu);

        await expect(backend.wrap(cek, bobJwk, header)).rejects.toThrowWithMessage(
          InvalidJoseHeaderError,
          'Invalid JOSE Header Parameter "apu".',
        );
      });

      it.each(invalidApvs)('should throw when the provided JOSE Header Parameter "apv" is invalid.', async (apv) => {
        Reflect.set(header.parameters, 'apv', apv);

        await expect(backend.wrap(cek, bobJwk, header)).rejects.toThrowWithMessage(
          InvalidJoseHeaderError,
          'Invalid JOSE Header Parameter "apv".',
        );
      });

      it('should throw when the provided JOSE Header Parameters "apu" and "apv" are equal.', async () => {
        await expect(backend.wrap(cek, bobJwk, sameApuApvHeader)).rejects.toThrowWithMessage(
          InvalidJoseHeaderError,
          'The JOSE Header Parameters "apu" and "apv" cannot be equal.',
        );
      });

      it('should throw when the provided JOSE Header Parameter "epk" and the provided Unwrap JSON Web Key have different Curves.', async () => {
        await expect(backend.wrap(cek, wrongJwk, header)).rejects.toThrowWithMessage(
          InvalidJoseHeaderError,
          'Invalid JOSE Header Parameter "epk".',
        );
      });

      it('should wrap the provided Content Encryption Key.', async () => {
        const wrapSpy = jest.spyOn(backend['aeskwBackend']!, 'wrap');
        await expect(backend.wrap(cek, bobJwk, ekHeader)).resolves.toStrictEqual(ek);
        expect(wrapSpy).toHaveBeenCalledOnce();
      });

      it('should wrap the provided Content Encryption Key with "apu".', async () => {
        const wrapSpy = jest.spyOn(backend['aeskwBackend']!, 'wrap');
        await expect(backend.wrap(cek, bobJwk, apuEkHeader)).resolves.toStrictEqual(apuEk);
        expect(wrapSpy).toHaveBeenCalledOnce();
      });

      it('should wrap the provided Content Encryption Key with "apv".', async () => {
        const wrapSpy = jest.spyOn(backend['aeskwBackend']!, 'wrap');
        await expect(backend.wrap(cek, bobJwk, apvEkHeader)).resolves.toStrictEqual(apvEk);
        expect(wrapSpy).toHaveBeenCalledOnce();
      });

      it('should wrap the provided Content Encryption Key with "apu" and "apv".', async () => {
        const wrapSpy = jest.spyOn(backend['aeskwBackend']!, 'wrap');
        await expect(backend.wrap(cek, bobJwk, apuAndApvEkHeader)).resolves.toStrictEqual(apuAndApvEk);
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
          'The JSON Web Encryption Algorithm only accepts "EC" and "OKP" JSON Web Keys.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "crv" does not match the required JSON Web Key Curve.', async () => {
        await expect(backend.unwrap(ek, wrongCrvJwk, header)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Key Parameter "crv" must be "P-256", "P-384", "P-521", "X25519", "X448" or "secp256k1".',
        );
      });

      it.each(invalidEpks)('should throw when the provided JOSE Header Parameter "epk" is invalid.', async (epk) => {
        Reflect.set(header.parameters, 'epk', epk);

        await expect(backend.unwrap(ek, bobJwk, header)).rejects.toThrowWithMessage(
          InvalidJoseHeaderError,
          'Invalid JOSE Header Parameter "epk".',
        );
      });

      it.each(invalidApus)('should throw when the provided JOSE Header Parameter "apu" is invalid.', async (apu) => {
        Reflect.set(header.parameters, 'apu', apu);

        await expect(backend.unwrap(ek, bobJwk, header)).rejects.toThrowWithMessage(
          InvalidJoseHeaderError,
          'Invalid JOSE Header Parameter "apu".',
        );
      });

      it.each(invalidApvs)('should throw when the provided JOSE Header Parameter "apv" is invalid.', async (apv) => {
        Reflect.set(header.parameters, 'apv', apv);

        await expect(backend.unwrap(ek, bobJwk, header)).rejects.toThrowWithMessage(
          InvalidJoseHeaderError,
          'Invalid JOSE Header Parameter "apv".',
        );
      });

      it('should throw when the provided JOSE Header Parameters "apu" and "apv" are equal.', async () => {
        await expect(backend.unwrap(ek, bobJwk, sameApuApvHeader)).rejects.toThrowWithMessage(
          InvalidJoseHeaderError,
          'The JOSE Header Parameters "apu" and "apv" cannot be equal.',
        );
      });

      it('should throw when the provided JOSE Header Parameter "epk" and the provided Unwrap JSON Web Key have different Curves.', async () => {
        await expect(backend.unwrap(ek, wrongJwk, header)).rejects.toThrowWithMessage(
          InvalidJoseHeaderError,
          'Invalid JOSE Header Parameter "epk".',
        );
      });

      it('should return the Content Encryption Key.', async () => {
        const unwrapSpy = jest.spyOn(backend['aeskwBackend']!, 'unwrap');
        await expect(backend.unwrap(ek, bobJwk, ekHeader)).resolves.toStrictEqual(cek);
        expect(unwrapSpy).toHaveBeenCalledOnce();
      });

      it('should return the Content Encryption Key with "apu".', async () => {
        const unwrapSpy = jest.spyOn(backend['aeskwBackend']!, 'unwrap');
        await expect(backend.unwrap(apuEk, bobJwk, apuEkHeader)).resolves.toStrictEqual(cek);
        expect(unwrapSpy).toHaveBeenCalledOnce();
      });

      it('should return the Content Encryption Key with "apv".', async () => {
        const unwrapSpy = jest.spyOn(backend['aeskwBackend']!, 'unwrap');
        await expect(backend.unwrap(apvEk, bobJwk, apvEkHeader)).resolves.toStrictEqual(cek);
        expect(unwrapSpy).toHaveBeenCalledOnce();
      });

      it('should return the Content Encryption Key with "apu" and "apv".', async () => {
        const unwrapSpy = jest.spyOn(backend['aeskwBackend']!, 'unwrap');
        await expect(backend.unwrap(apuAndApvEk, bobJwk, apuAndApvEkHeader)).resolves.toStrictEqual(cek);
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
          'The JSON Web Encryption Algorithm only accepts "EC" and "OKP" JSON Web Keys.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "crv" does not match the required JSON Web Key Curve.', async () => {
        await expect(backend.generateContentEncryptionKey(wrongCrvJwk, header)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Key Parameter "crv" must be "P-256", "P-384", "P-521", "X25519", "X448" or "secp256k1".',
        );
      });

      it.each(invalidEpks)('should throw when the provided JOSE Header Parameter "epk" is invalid.', async (epk) => {
        Reflect.set(header.parameters, 'epk', epk);

        await expect(backend.generateContentEncryptionKey(bobJwk, header)).rejects.toThrowWithMessage(
          InvalidJoseHeaderError,
          'Invalid JOSE Header Parameter "epk".',
        );
      });

      it.each(invalidApus)('should throw when the provided JOSE Header Parameter "apu" is invalid.', async (apu) => {
        Reflect.set(header.parameters, 'apu', apu);

        await expect(backend.generateContentEncryptionKey(bobJwk, header)).rejects.toThrowWithMessage(
          InvalidJoseHeaderError,
          'Invalid JOSE Header Parameter "apu".',
        );
      });

      it.each(invalidApvs)('should throw when the provided JOSE Header Parameter "apv" is invalid.', async (apv) => {
        Reflect.set(header.parameters, 'apv', apv);

        await expect(backend.generateContentEncryptionKey(bobJwk, header)).rejects.toThrowWithMessage(
          InvalidJoseHeaderError,
          'Invalid JOSE Header Parameter "apv".',
        );
      });

      it('should throw when the provided JOSE Header Parameters "apu" and "apv" are equal.', async () => {
        await expect(backend.generateContentEncryptionKey(bobJwk, sameApuApvHeader)).rejects.toThrowWithMessage(
          InvalidJoseHeaderError,
          'The JOSE Header Parameters "apu" and "apv" cannot be equal.',
        );
      });

      it('should return the Content Encryption Key.', async () => {
        await expect(backend.generateContentEncryptionKey(bobJwk, ekHeader)).resolves.toStrictEqual(cek);
      });

      it('should return the Content Encryption Key with "apu".', async () => {
        await expect(backend.generateContentEncryptionKey(bobJwk, apuEkHeader)).resolves.toStrictEqual(cek);
      });

      it('should return the Content Encryption Key with "apv".', async () => {
        await expect(backend.generateContentEncryptionKey(bobJwk, apvEkHeader)).resolves.toStrictEqual(cek);
      });

      it('should return the Content Encryption Key with "apu" and "apv".', async () => {
        await expect(backend.generateContentEncryptionKey(bobJwk, apuAndApvEkHeader)).resolves.toStrictEqual(cek);
      });
    });
  });

  describe('ECDH-ES+A192KW', () => {
    const backend = new ECDHESJsonWebEncryptionKeyManagementBackend('ECDH-ES+A192KW');

    const cek = Buffer.from('AAECAwQFBgcICQoLDA0ODw', 'base64url');

    const ek = Buffer.from('riTxC0UGCRV8vYCR022zskFfOMhOD-ms', 'base64url');
    const apuEk = Buffer.from('WciBje0F74ivHUXyJ_Jrydkqc2TZSbHZ', 'base64url');
    const apvEk = Buffer.from('Qb_fv3jJzG7-PQknVGP0gBo3p4o6HoSt', 'base64url');
    const apuAndApvEk = Buffer.from('Wc4q4jHLA-H3pmhufwkZ0pN3Z8w6ugdO', 'base64url');

    let header: JsonWebEncryptionHeader<ECDHESJsonWebEncryptionKeyManagementHeaderParameters>;

    const sameApuApvHeader = new JsonWebEncryptionHeader<ECDHESJsonWebEncryptionKeyManagementHeaderParameters>({
      alg: 'ECDH-ES+A192KW',
      enc: 'A128GCM',
      apu: 'Qm9i',
      apv: 'Qm9i',
      epk: aliceJwk.toJSON() as EllipticCurveJsonWebKeyParameters | OctetKeyPairJsonWebKeyParameters,
    });

    const ekHeader = new JsonWebEncryptionHeader<ECDHESJsonWebEncryptionKeyManagementHeaderParameters>({
      alg: 'ECDH-ES',
      enc: 'A128GCM',
      epk: aliceJwk.toJSON() as EllipticCurveJsonWebKeyParameters | OctetKeyPairJsonWebKeyParameters,
    });

    const apuEkHeader = new JsonWebEncryptionHeader<ECDHESJsonWebEncryptionKeyManagementHeaderParameters>({
      alg: 'ECDH-ES',
      enc: 'A128GCM',
      apu: 'QWxpY2U',
      epk: aliceJwk.toJSON() as EllipticCurveJsonWebKeyParameters | OctetKeyPairJsonWebKeyParameters,
    });

    const apvEkHeader = new JsonWebEncryptionHeader<ECDHESJsonWebEncryptionKeyManagementHeaderParameters>({
      alg: 'ECDH-ES',
      enc: 'A128GCM',
      apv: 'Qm9i',
      epk: aliceJwk.toJSON() as EllipticCurveJsonWebKeyParameters | OctetKeyPairJsonWebKeyParameters,
    });

    const apuAndApvEkHeader = new JsonWebEncryptionHeader<ECDHESJsonWebEncryptionKeyManagementHeaderParameters>({
      alg: 'ECDH-ES',
      enc: 'A128GCM',
      apu: 'QWxpY2U',
      apv: 'Qm9i',
      epk: aliceJwk.toJSON() as EllipticCurveJsonWebKeyParameters | OctetKeyPairJsonWebKeyParameters,
    });

    beforeEach(() => {
      header = new JsonWebEncryptionHeader<ECDHESJsonWebEncryptionKeyManagementHeaderParameters>({
        alg: 'ECDH-ES+A192KW',
        enc: 'A128GCM',
        apu: 'QWxpY2U',
        apv: 'Qm9i',
        epk: aliceJwk.toJSON() as EllipticCurveJsonWebKeyParameters | OctetKeyPairJsonWebKeyParameters,
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
          'The JSON Web Encryption Algorithm only accepts "EC" and "OKP" JSON Web Keys.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "crv" does not match the required JSON Web Key Curve.', async () => {
        await expect(backend.wrap(cek, wrongCrvJwk, header)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Key Parameter "crv" must be "P-256", "P-384", "P-521", "X25519", "X448" or "secp256k1".',
        );
      });

      it.each(invalidEpks)('should throw when the provided JOSE Header Parameter "epk" is invalid.', async (epk) => {
        Reflect.set(header.parameters, 'epk', epk);

        await expect(backend.wrap(cek, bobJwk, header)).rejects.toThrowWithMessage(
          InvalidJoseHeaderError,
          'Invalid JOSE Header Parameter "epk".',
        );
      });

      it.each(invalidApus)('should throw when the provided JOSE Header Parameter "apu" is invalid.', async (apu) => {
        Reflect.set(header.parameters, 'apu', apu);

        await expect(backend.wrap(cek, bobJwk, header)).rejects.toThrowWithMessage(
          InvalidJoseHeaderError,
          'Invalid JOSE Header Parameter "apu".',
        );
      });

      it.each(invalidApvs)('should throw when the provided JOSE Header Parameter "apv" is invalid.', async (apv) => {
        Reflect.set(header.parameters, 'apv', apv);

        await expect(backend.wrap(cek, bobJwk, header)).rejects.toThrowWithMessage(
          InvalidJoseHeaderError,
          'Invalid JOSE Header Parameter "apv".',
        );
      });

      it('should throw when the provided JOSE Header Parameters "apu" and "apv" are equal.', async () => {
        await expect(backend.wrap(cek, bobJwk, sameApuApvHeader)).rejects.toThrowWithMessage(
          InvalidJoseHeaderError,
          'The JOSE Header Parameters "apu" and "apv" cannot be equal.',
        );
      });

      it('should throw when the provided JOSE Header Parameter "epk" and the provided Unwrap JSON Web Key have different Curves.', async () => {
        await expect(backend.wrap(cek, wrongJwk, header)).rejects.toThrowWithMessage(
          InvalidJoseHeaderError,
          'Invalid JOSE Header Parameter "epk".',
        );
      });

      it('should wrap the provided Content Encryption Key.', async () => {
        const wrapSpy = jest.spyOn(backend['aeskwBackend']!, 'wrap');
        await expect(backend.wrap(cek, bobJwk, ekHeader)).resolves.toStrictEqual(ek);
        expect(wrapSpy).toHaveBeenCalledOnce();
      });

      it('should wrap the provided Content Encryption Key with "apu".', async () => {
        const wrapSpy = jest.spyOn(backend['aeskwBackend']!, 'wrap');
        await expect(backend.wrap(cek, bobJwk, apuEkHeader)).resolves.toStrictEqual(apuEk);
        expect(wrapSpy).toHaveBeenCalledOnce();
      });

      it('should wrap the provided Content Encryption Key with "apv".', async () => {
        const wrapSpy = jest.spyOn(backend['aeskwBackend']!, 'wrap');
        await expect(backend.wrap(cek, bobJwk, apvEkHeader)).resolves.toStrictEqual(apvEk);
        expect(wrapSpy).toHaveBeenCalledOnce();
      });

      it('should wrap the provided Content Encryption Key with "apu" and "apv".', async () => {
        const wrapSpy = jest.spyOn(backend['aeskwBackend']!, 'wrap');
        await expect(backend.wrap(cek, bobJwk, apuAndApvEkHeader)).resolves.toStrictEqual(apuAndApvEk);
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
          'The JSON Web Encryption Algorithm only accepts "EC" and "OKP" JSON Web Keys.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "crv" does not match the required JSON Web Key Curve.', async () => {
        await expect(backend.unwrap(ek, wrongCrvJwk, header)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Key Parameter "crv" must be "P-256", "P-384", "P-521", "X25519", "X448" or "secp256k1".',
        );
      });

      it.each(invalidEpks)('should throw when the provided JOSE Header Parameter "epk" is invalid.', async (epk) => {
        Reflect.set(header.parameters, 'epk', epk);

        await expect(backend.unwrap(ek, bobJwk, header)).rejects.toThrowWithMessage(
          InvalidJoseHeaderError,
          'Invalid JOSE Header Parameter "epk".',
        );
      });

      it.each(invalidApus)('should throw when the provided JOSE Header Parameter "apu" is invalid.', async (apu) => {
        Reflect.set(header.parameters, 'apu', apu);

        await expect(backend.unwrap(ek, bobJwk, header)).rejects.toThrowWithMessage(
          InvalidJoseHeaderError,
          'Invalid JOSE Header Parameter "apu".',
        );
      });

      it.each(invalidApvs)('should throw when the provided JOSE Header Parameter "apv" is invalid.', async (apv) => {
        Reflect.set(header.parameters, 'apv', apv);

        await expect(backend.unwrap(ek, bobJwk, header)).rejects.toThrowWithMessage(
          InvalidJoseHeaderError,
          'Invalid JOSE Header Parameter "apv".',
        );
      });

      it('should throw when the provided JOSE Header Parameters "apu" and "apv" are equal.', async () => {
        await expect(backend.unwrap(ek, bobJwk, sameApuApvHeader)).rejects.toThrowWithMessage(
          InvalidJoseHeaderError,
          'The JOSE Header Parameters "apu" and "apv" cannot be equal.',
        );
      });

      it('should throw when the provided JOSE Header Parameter "epk" and the provided Unwrap JSON Web Key have different Curves.', async () => {
        await expect(backend.unwrap(ek, wrongJwk, header)).rejects.toThrowWithMessage(
          InvalidJoseHeaderError,
          'Invalid JOSE Header Parameter "epk".',
        );
      });

      it('should return the Content Encryption Key.', async () => {
        const unwrapSpy = jest.spyOn(backend['aeskwBackend']!, 'unwrap');
        await expect(backend.unwrap(ek, bobJwk, ekHeader)).resolves.toStrictEqual(cek);
        expect(unwrapSpy).toHaveBeenCalledOnce();
      });

      it('should return the Content Encryption Key with "apu".', async () => {
        const unwrapSpy = jest.spyOn(backend['aeskwBackend']!, 'unwrap');
        await expect(backend.unwrap(apuEk, bobJwk, apuEkHeader)).resolves.toStrictEqual(cek);
        expect(unwrapSpy).toHaveBeenCalledOnce();
      });

      it('should return the Content Encryption Key with "apv".', async () => {
        const unwrapSpy = jest.spyOn(backend['aeskwBackend']!, 'unwrap');
        await expect(backend.unwrap(apvEk, bobJwk, apvEkHeader)).resolves.toStrictEqual(cek);
        expect(unwrapSpy).toHaveBeenCalledOnce();
      });

      it('should return the Content Encryption Key with "apu" and "apv".', async () => {
        const unwrapSpy = jest.spyOn(backend['aeskwBackend']!, 'unwrap');
        await expect(backend.unwrap(apuAndApvEk, bobJwk, apuAndApvEkHeader)).resolves.toStrictEqual(cek);
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
          'The JSON Web Encryption Algorithm only accepts "EC" and "OKP" JSON Web Keys.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "crv" does not match the required JSON Web Key Curve.', async () => {
        await expect(backend.generateContentEncryptionKey(wrongCrvJwk, header)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Key Parameter "crv" must be "P-256", "P-384", "P-521", "X25519", "X448" or "secp256k1".',
        );
      });

      it.each(invalidEpks)('should throw when the provided JOSE Header Parameter "epk" is invalid.', async (epk) => {
        Reflect.set(header.parameters, 'epk', epk);

        await expect(backend.generateContentEncryptionKey(bobJwk, header)).rejects.toThrowWithMessage(
          InvalidJoseHeaderError,
          'Invalid JOSE Header Parameter "epk".',
        );
      });

      it.each(invalidApus)('should throw when the provided JOSE Header Parameter "apu" is invalid.', async (apu) => {
        Reflect.set(header.parameters, 'apu', apu);

        await expect(backend.generateContentEncryptionKey(bobJwk, header)).rejects.toThrowWithMessage(
          InvalidJoseHeaderError,
          'Invalid JOSE Header Parameter "apu".',
        );
      });

      it.each(invalidApvs)('should throw when the provided JOSE Header Parameter "apv" is invalid.', async (apv) => {
        Reflect.set(header.parameters, 'apv', apv);

        await expect(backend.generateContentEncryptionKey(bobJwk, header)).rejects.toThrowWithMessage(
          InvalidJoseHeaderError,
          'Invalid JOSE Header Parameter "apv".',
        );
      });

      it('should throw when the provided JOSE Header Parameters "apu" and "apv" are equal.', async () => {
        await expect(backend.generateContentEncryptionKey(bobJwk, sameApuApvHeader)).rejects.toThrowWithMessage(
          InvalidJoseHeaderError,
          'The JOSE Header Parameters "apu" and "apv" cannot be equal.',
        );
      });

      it('should return the Content Encryption Key.', async () => {
        await expect(backend.generateContentEncryptionKey(bobJwk, ekHeader)).resolves.toStrictEqual(cek);
      });

      it('should return the Content Encryption Key with "apu".', async () => {
        await expect(backend.generateContentEncryptionKey(bobJwk, apuEkHeader)).resolves.toStrictEqual(cek);
      });

      it('should return the Content Encryption Key with "apv".', async () => {
        await expect(backend.generateContentEncryptionKey(bobJwk, apvEkHeader)).resolves.toStrictEqual(cek);
      });

      it('should return the Content Encryption Key with "apu" and "apv".', async () => {
        await expect(backend.generateContentEncryptionKey(bobJwk, apuAndApvEkHeader)).resolves.toStrictEqual(cek);
      });
    });
  });

  describe('ECDH-ES+A256KW', () => {
    const backend = new ECDHESJsonWebEncryptionKeyManagementBackend('ECDH-ES+A256KW');

    const cek = Buffer.from('AAECAwQFBgcICQoLDA0ODw', 'base64url');

    const ek = Buffer.from('gWvAv5k6x2zo61kdosw0Ztx5SHwlYUxM', 'base64url');
    const apuEk = Buffer.from('esnqpN0kPDUUwsHAvvFGz4Kd3jHRpqpm', 'base64url');
    const apvEk = Buffer.from('wlrQUCWdmF7Bi2U5Af7lF-3W1rLPwruh', 'base64url');
    const apuAndApvEk = Buffer.from('jGS3GB2G8-Yy62oWb_LoCQqqRGO9PZPt', 'base64url');

    let header: JsonWebEncryptionHeader<ECDHESJsonWebEncryptionKeyManagementHeaderParameters>;

    const sameApuApvHeader = new JsonWebEncryptionHeader<ECDHESJsonWebEncryptionKeyManagementHeaderParameters>({
      alg: 'ECDH-ES+A256KW',
      enc: 'A128GCM',
      apu: 'Qm9i',
      apv: 'Qm9i',
      epk: aliceJwk.toJSON() as EllipticCurveJsonWebKeyParameters | OctetKeyPairJsonWebKeyParameters,
    });

    const ekHeader = new JsonWebEncryptionHeader<ECDHESJsonWebEncryptionKeyManagementHeaderParameters>({
      alg: 'ECDH-ES',
      enc: 'A128GCM',
      epk: aliceJwk.toJSON() as EllipticCurveJsonWebKeyParameters | OctetKeyPairJsonWebKeyParameters,
    });

    const apuEkHeader = new JsonWebEncryptionHeader<ECDHESJsonWebEncryptionKeyManagementHeaderParameters>({
      alg: 'ECDH-ES',
      enc: 'A128GCM',
      apu: 'QWxpY2U',
      epk: aliceJwk.toJSON() as EllipticCurveJsonWebKeyParameters | OctetKeyPairJsonWebKeyParameters,
    });

    const apvEkHeader = new JsonWebEncryptionHeader<ECDHESJsonWebEncryptionKeyManagementHeaderParameters>({
      alg: 'ECDH-ES',
      enc: 'A128GCM',
      apv: 'Qm9i',
      epk: aliceJwk.toJSON() as EllipticCurveJsonWebKeyParameters | OctetKeyPairJsonWebKeyParameters,
    });

    const apuAndApvEkHeader = new JsonWebEncryptionHeader<ECDHESJsonWebEncryptionKeyManagementHeaderParameters>({
      alg: 'ECDH-ES',
      enc: 'A128GCM',
      apu: 'QWxpY2U',
      apv: 'Qm9i',
      epk: aliceJwk.toJSON() as EllipticCurveJsonWebKeyParameters | OctetKeyPairJsonWebKeyParameters,
    });

    beforeEach(() => {
      header = new JsonWebEncryptionHeader<ECDHESJsonWebEncryptionKeyManagementHeaderParameters>({
        alg: 'ECDH-ES+A256KW',
        enc: 'A128GCM',
        apu: 'QWxpY2U',
        apv: 'Qm9i',
        epk: aliceJwk.toJSON() as EllipticCurveJsonWebKeyParameters | OctetKeyPairJsonWebKeyParameters,
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
          'The JSON Web Encryption Algorithm only accepts "EC" and "OKP" JSON Web Keys.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "crv" does not match the required JSON Web Key Curve.', async () => {
        await expect(backend.wrap(cek, wrongCrvJwk, header)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Key Parameter "crv" must be "P-256", "P-384", "P-521", "X25519", "X448" or "secp256k1".',
        );
      });

      it.each(invalidEpks)('should throw when the provided JOSE Header Parameter "epk" is invalid.', async (epk) => {
        Reflect.set(header.parameters, 'epk', epk);

        await expect(backend.wrap(cek, bobJwk, header)).rejects.toThrowWithMessage(
          InvalidJoseHeaderError,
          'Invalid JOSE Header Parameter "epk".',
        );
      });

      it.each(invalidApus)('should throw when the provided JOSE Header Parameter "apu" is invalid.', async (apu) => {
        Reflect.set(header.parameters, 'apu', apu);

        await expect(backend.wrap(cek, bobJwk, header)).rejects.toThrowWithMessage(
          InvalidJoseHeaderError,
          'Invalid JOSE Header Parameter "apu".',
        );
      });

      it.each(invalidApvs)('should throw when the provided JOSE Header Parameter "apv" is invalid.', async (apv) => {
        Reflect.set(header.parameters, 'apv', apv);

        await expect(backend.wrap(cek, bobJwk, header)).rejects.toThrowWithMessage(
          InvalidJoseHeaderError,
          'Invalid JOSE Header Parameter "apv".',
        );
      });

      it('should throw when the provided JOSE Header Parameters "apu" and "apv" are equal.', async () => {
        await expect(backend.wrap(cek, bobJwk, sameApuApvHeader)).rejects.toThrowWithMessage(
          InvalidJoseHeaderError,
          'The JOSE Header Parameters "apu" and "apv" cannot be equal.',
        );
      });

      it('should throw when the provided JOSE Header Parameter "epk" and the provided Unwrap JSON Web Key have different Curves.', async () => {
        await expect(backend.wrap(cek, wrongJwk, header)).rejects.toThrowWithMessage(
          InvalidJoseHeaderError,
          'Invalid JOSE Header Parameter "epk".',
        );
      });

      it('should wrap the provided Content Encryption Key.', async () => {
        const wrapSpy = jest.spyOn(backend['aeskwBackend']!, 'wrap');
        await expect(backend.wrap(cek, bobJwk, ekHeader)).resolves.toStrictEqual(ek);
        expect(wrapSpy).toHaveBeenCalledOnce();
      });

      it('should wrap the provided Content Encryption Key with "apu".', async () => {
        const wrapSpy = jest.spyOn(backend['aeskwBackend']!, 'wrap');
        await expect(backend.wrap(cek, bobJwk, apuEkHeader)).resolves.toStrictEqual(apuEk);
        expect(wrapSpy).toHaveBeenCalledOnce();
      });

      it('should wrap the provided Content Encryption Key with "apv".', async () => {
        const wrapSpy = jest.spyOn(backend['aeskwBackend']!, 'wrap');
        await expect(backend.wrap(cek, bobJwk, apvEkHeader)).resolves.toStrictEqual(apvEk);
        expect(wrapSpy).toHaveBeenCalledOnce();
      });

      it('should wrap the provided Content Encryption Key with "apu" and "apv".', async () => {
        const wrapSpy = jest.spyOn(backend['aeskwBackend']!, 'wrap');
        await expect(backend.wrap(cek, bobJwk, apuAndApvEkHeader)).resolves.toStrictEqual(apuAndApvEk);
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
          'The JSON Web Encryption Algorithm only accepts "EC" and "OKP" JSON Web Keys.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "crv" does not match the required JSON Web Key Curve.', async () => {
        await expect(backend.unwrap(ek, wrongCrvJwk, header)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Key Parameter "crv" must be "P-256", "P-384", "P-521", "X25519", "X448" or "secp256k1".',
        );
      });

      it.each(invalidEpks)('should throw when the provided JOSE Header Parameter "epk" is invalid.', async (epk) => {
        Reflect.set(header.parameters, 'epk', epk);

        await expect(backend.unwrap(ek, bobJwk, header)).rejects.toThrowWithMessage(
          InvalidJoseHeaderError,
          'Invalid JOSE Header Parameter "epk".',
        );
      });

      it.each(invalidApus)('should throw when the provided JOSE Header Parameter "apu" is invalid.', async (apu) => {
        Reflect.set(header.parameters, 'apu', apu);

        await expect(backend.unwrap(ek, bobJwk, header)).rejects.toThrowWithMessage(
          InvalidJoseHeaderError,
          'Invalid JOSE Header Parameter "apu".',
        );
      });

      it.each(invalidApvs)('should throw when the provided JOSE Header Parameter "apv" is invalid.', async (apv) => {
        Reflect.set(header.parameters, 'apv', apv);

        await expect(backend.unwrap(ek, bobJwk, header)).rejects.toThrowWithMessage(
          InvalidJoseHeaderError,
          'Invalid JOSE Header Parameter "apv".',
        );
      });

      it('should throw when the provided JOSE Header Parameters "apu" and "apv" are equal.', async () => {
        await expect(backend.unwrap(ek, bobJwk, sameApuApvHeader)).rejects.toThrowWithMessage(
          InvalidJoseHeaderError,
          'The JOSE Header Parameters "apu" and "apv" cannot be equal.',
        );
      });

      it('should throw when the provided JOSE Header Parameter "epk" and the provided Unwrap JSON Web Key have different Curves.', async () => {
        await expect(backend.unwrap(ek, wrongJwk, header)).rejects.toThrowWithMessage(
          InvalidJoseHeaderError,
          'Invalid JOSE Header Parameter "epk".',
        );
      });

      it('should return the Content Encryption Key.', async () => {
        const unwrapSpy = jest.spyOn(backend['aeskwBackend']!, 'unwrap');
        await expect(backend.unwrap(ek, bobJwk, ekHeader)).resolves.toStrictEqual(cek);
        expect(unwrapSpy).toHaveBeenCalledOnce();
      });

      it('should return the Content Encryption Key with "apu".', async () => {
        const unwrapSpy = jest.spyOn(backend['aeskwBackend']!, 'unwrap');
        await expect(backend.unwrap(apuEk, bobJwk, apuEkHeader)).resolves.toStrictEqual(cek);
        expect(unwrapSpy).toHaveBeenCalledOnce();
      });

      it('should return the Content Encryption Key with "apv".', async () => {
        const unwrapSpy = jest.spyOn(backend['aeskwBackend']!, 'unwrap');
        await expect(backend.unwrap(apvEk, bobJwk, apvEkHeader)).resolves.toStrictEqual(cek);
        expect(unwrapSpy).toHaveBeenCalledOnce();
      });

      it('should return the Content Encryption Key with "apu" and "apv".', async () => {
        const unwrapSpy = jest.spyOn(backend['aeskwBackend']!, 'unwrap');
        await expect(backend.unwrap(apuAndApvEk, bobJwk, apuAndApvEkHeader)).resolves.toStrictEqual(cek);
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
          'The JSON Web Encryption Algorithm only accepts "EC" and "OKP" JSON Web Keys.',
        );
      });

      it('should throw when the provided JSON Web Key Parameter "crv" does not match the required JSON Web Key Curve.', async () => {
        await expect(backend.generateContentEncryptionKey(wrongCrvJwk, header)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The JSON Web Key Parameter "crv" must be "P-256", "P-384", "P-521", "X25519", "X448" or "secp256k1".',
        );
      });

      it.each(invalidEpks)('should throw when the provided JOSE Header Parameter "epk" is invalid.', async (epk) => {
        Reflect.set(header.parameters, 'epk', epk);

        await expect(backend.generateContentEncryptionKey(bobJwk, header)).rejects.toThrowWithMessage(
          InvalidJoseHeaderError,
          'Invalid JOSE Header Parameter "epk".',
        );
      });

      it.each(invalidApus)('should throw when the provided JOSE Header Parameter "apu" is invalid.', async (apu) => {
        Reflect.set(header.parameters, 'apu', apu);

        await expect(backend.generateContentEncryptionKey(bobJwk, header)).rejects.toThrowWithMessage(
          InvalidJoseHeaderError,
          'Invalid JOSE Header Parameter "apu".',
        );
      });

      it.each(invalidApvs)('should throw when the provided JOSE Header Parameter "apv" is invalid.', async (apv) => {
        Reflect.set(header.parameters, 'apv', apv);

        await expect(backend.generateContentEncryptionKey(bobJwk, header)).rejects.toThrowWithMessage(
          InvalidJoseHeaderError,
          'Invalid JOSE Header Parameter "apv".',
        );
      });

      it('should throw when the provided JOSE Header Parameters "apu" and "apv" are equal.', async () => {
        await expect(backend.generateContentEncryptionKey(bobJwk, sameApuApvHeader)).rejects.toThrowWithMessage(
          InvalidJoseHeaderError,
          'The JOSE Header Parameters "apu" and "apv" cannot be equal.',
        );
      });

      it('should return the Content Encryption Key.', async () => {
        await expect(backend.generateContentEncryptionKey(bobJwk, ekHeader)).resolves.toStrictEqual(cek);
      });

      it('should return the Content Encryption Key with "apu".', async () => {
        await expect(backend.generateContentEncryptionKey(bobJwk, apuEkHeader)).resolves.toStrictEqual(cek);
      });

      it('should return the Content Encryption Key with "apv".', async () => {
        await expect(backend.generateContentEncryptionKey(bobJwk, apvEkHeader)).resolves.toStrictEqual(cek);
      });

      it('should return the Content Encryption Key with "apu" and "apv".', async () => {
        await expect(backend.generateContentEncryptionKey(bobJwk, apuAndApvEkHeader)).resolves.toStrictEqual(cek);
      });
    });
  });
});
