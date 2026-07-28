import { Buffer } from 'buffer';
import crypto from 'crypto';

import { InvalidJsonWebEncryptionError } from '../../../../errors/invalid-jsonwebencryption.error';
import { InvalidJsonWebKeyError } from '../../../../errors/invalid-jsonwebkey.error';
import { JsonWebEncryptionHeader } from '../../../../jwe/jsonwebencryption-header';
import { EllipticCurveJsonWebKey } from '../../../jwk/ec/elliptic-curve.jsonwebkey';
import { RsaJsonWebKey } from '../../../jwk/rsa/rsa.jsonwebkey';
import { RSAESJsonWebEncryptionKeyManagementBackend } from './rsaes-jsonwebencryption-key-management.backend';

jest.mock<typeof crypto>('crypto', () => ({
  ...jest.requireActual('crypto'),
  randomBytes: jest.fn().mockImplementation((size, cb) => cb(null, Buffer.from([...Array(size).keys()]))),
}));

describe('RSAES JSON Web Encryption Key Management Backend', () => {
  const cek = Buffer.from('AAECAwQFBgcICQoLDA0ODw', 'base64url');

  const publicJwk = new RsaJsonWebKey({
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

  const privateJwk = new RsaJsonWebKey({
    ...publicJwk.parameters,
    d:
      'cc2YrWia9LGRad0SMe0PrlmeeHSyRe5-u--QJcP4uF_5LYYzXIsjDJ9_iYh0S_YY' +
      'e6bLjqHOSp44OHvJqoXMX5j3-ECKnNjnUHMtRB2awXGBqBOhB8TqoQXgmXDi1jx_' +
      '6Fu8xH-vaSfpwrsN-0QzIcYHil6b8hwE0f0r6istBmL7iayJbnONp7na9ow2fUQl' +
      'nr41vsHZa4knTZ2E2kq5ntgaXlF6AIdc4DD_BZpf2alEbhQMX9T168ZsSyAs7wKS' +
      'd3ivhHRQayXEapUfZ_ykvnF4-DoVI1iRoowgZ-dlnv4Ff3YrKQ3Zv3uHJcF1BtWQ' +
      'VipOIHx4GyIc4bmTSA5PEQ',
    p:
      '-ZFuDg38cG-e5L6h1Jbn8ngifWgHx8m1gybkY7yEpU1V02fvQAMI1XG-1WpZm2xj' +
      'j218wNCj0BCEdmdBqZMk5RlzLagtfzQ3rPO-ucYPZ_SDmy8Udzr-sZLCqMFyLtxk' +
      'gMfGo4QZ6UJWYpTCCmZ92nS_pa4ePrQdlpnS4DLv_SM',
    q:
      'y1YdZtsbYfCOdsYBZrDpcvubwMN2fKRAzETYW5sqYv8XkxHG1J1zHH-zWJBQfZhT' +
      'biHPgHvoaFykEm9xhuA77RFGRXxFUrGBtfqIx_OG-kRWudmH83EyMzMoKQaW98RX' +
      'WqRO1JDlcs4_vzf_KN63zQKv5i4UdiiObQkZCYIOVUk',
    dp:
      'vqtDX-2DjgtZY_3Y-eiJMRBjmVgfiZ4r1RWjrCddWEVrauafPVKULy6F09s6tqnq' +
      'rqvBgjZk0ROtgCCHZB0NNRNqkdlJWUP1vWdDsf8FyjBfU_J2OlmSOOydV_zjVbX_' +
      '-vumYUsN2M5b3Vk1nmiLgplryhLq_JDzghnnqG6CN-0',
    dq:
      'tKczxBhSwbcpu5i70fLH1iJ5BNAkSyTbdSCNYQYAqKee2Elo76lbhixmuP6upIdb' +
      'SHO9mZd8qov0MXTV1lEOrNc2KbH5HTkb1wRZ1dwlReDFdKUxxjYBtb9zpM93_XVx' +
      'btSgPPbnBBL-S_OCPVtyzS_f-49hGoF52KHGns3v0hE',
    qi:
      'C4q9uIi-1fYhE0NTWVNzdhSi7fA3uznTWaW1X5LWBF4gBOcWvMMTfOZEaPjtY2WP' +
      'XaTWU4bdVN0GgktVLUDPLrSj533W1cOQZb_mm_7BFNrleelruT87bZhWPYQ979kl' +
      '6590ySgbH81pEM8FQW1JBATz0MYtUNZAt8N360vayE4',
  });

  const wrongAlgJwk = new RsaJsonWebKey({ ...privateJwk.parameters, alg: 'RS256' });

  const wrongKtyJwk = new EllipticCurveJsonWebKey({
    kty: 'EC',
    crv: 'P-256',
    x: '4c_cS6IT6jaVQeobt_6BDCTmzBaBOTmmiSCpjd5a6Og',
    y: 'mnrPnCFTDkGdEwilabaqM7DzwlAFgetZTmP9ycHPxF8',
    d: 'bwVX6Vx-TOfGKYOPAcu2xhaj3JUzs-McsC-suaHnFBo',
  });

  const wrongEk = Buffer.from('lHuMKm2fxX76BzBvQrVxDA5w3g3-oOqJDP4l5UeCSCY', 'base64url');

  const wrongJwk = new RsaJsonWebKey({
    kty: 'RSA',
    n:
      'mtgsnD4B-xxzdYNrNrbIaOskyYQ4XzocDO8Qi4JNE5rtMVopjIRPpo_FJlXM-pBE' +
      'XAdUDM3mneq8pthe5ikbpzod1ZkPlwFnT7UNLxLqeht5Q8zwKrFlUmEQ8K-c5s8e' +
      'nQCPryDm7CfNjjF1wjOinn5LVuGI7cD0cYTcAg3fwrrvjqGskLDTNcdQfYjWMt7P' +
      'b_UeUGWEepSqIZx92Bg3bn4cUXfPpi5T7woPavmoI86bDWTTUL7uobmwB0qhTiF9' +
      'Uv9Y0_vzilYpKQEqIEsz0nslD5kC0RKAi8xM8i65UarcWxOT4JCTtWUwBlxozg2S' +
      'PpntPMfxpbnQtqQNP86m9Q',
    e: 'AQAB',
    d:
      'DtvDDhwaIw9EGgjqExY_jWfRACBWq3afRfNzxjtS65hwfc2d0ozIut4taCQQFxQc' +
      'ZytR2qewY0No5ma5VoMn0uht__bfytj44appMTTyuJRl0sZ53lLm-txzHHFxkClc' +
      'UesBnqe82PjpzeT7nI7JYkWSs6vRMKVVH4aE-RJ9QAl7Zflv_Z2l6wwmpgCQ9gfj' +
      'T69PuRAMh8G1PtsGUUTNh471-iInvQgDqznIOM2s0JA-mYyX6hQyiD2B4oB1k54q' +
      'rNf5_uUK2V4vNJcennB1-k8mj6-HKh_AQco9x-rSJnI6ZPa929iJ9k-tO32kSmZ9' +
      'c2t-yoM-oZ6Nqa4lrhPpqQ',
    p:
      'zBWarMZOmP_ZNGRkjRmD07d5BHFNxCDNx1J4exZK9Ir2o_BU67qX8d22K1mAGj_8' +
      'WgA1jOgj6MFpe1FGR72dlOWRf9Zgr56eBAD8Plcde2QtLmZ7l8B_a6AxXjbOMbR_' +
      'HCQIBxqX-QbOWmuyYUs7P7ytC6uobGwQ66zO87HIhik',
    q:
      'wjv2YbiB5YKxEiYuBr3fBlzba_QLz2E03iAL1WWVgARUaUiDUlo4bpNUVz85ZO2o' +
      '8xg6mnkWbG5xPCuY27Qf4Jx153J0xsoK5pZ0t0p-RiS4Zhq3TyyA3rI1IU4AcmT4' +
      'BJiTNH7MSqgsDnnegAtnj_1nZGvSxUDwWwez-DInO-0',
    dp:
      'm_3DbV5ig0XEEuzNgqBHCBPMF143b7sXLsxVtNd0UXjKTsKLVmcYbtHlxTqy1N2l' +
      'mHFifSKPGACGDLExw_ImOcJDNXB6FKJr62mJZGkX6tHGSxogS_ziKDSYp4fCkXGC' +
      'WtMbo7prAPh3z9tTzFRBpFUl-66onL75K_q5cMGqIQk',
    dq:
      'Z19ARkvLHhnLIWyebEoa6yj6Ql709h6240zM33qb8TDct9e2xFpt1DOm3HQymIt_' +
      'sjj_33x4OachrrNJPAyGNqUufspEahPXb1c9sNr9j1k1pmmri4CU6XCQpDP-OuOP' +
      't-p31aVyFn2gTOgBScZIDLMBlslnuEFSajAUURBoHxU',
    qi:
      'jdD0nZgDn1UqpphDh7ozoZDzK_8ILhZXko9bixdfn4p9qdK_MX2WHofM9HH3iIgJ' +
      'QI9aaulFhKTGfV-1WJEgLPa60HRWj2jORkxjtBgmQwYrjRij48aU61DvkWHLpNdJ' +
      'hRBrbYG0XPbADz06xsJL3A8kRyghBXO_ULCE3OHqiYo',
  });

  describe('RSA-OAEP', () => {
    const backend = new RSAESJsonWebEncryptionKeyManagementBackend('RSA-OAEP');

    const header = new JsonWebEncryptionHeader({ alg: 'RSA-OAEP', enc: 'A128GCM' });

    let ek!: Buffer;

    describe('hash', () => {
      it('should be "sha-1".', () => {
        expect(backend['hash']).toStrictEqual('sha-1');
      });
    });

    describe('padding', () => {
      it('should have the value of crypto.constants.RSA_PKCS1_OAEP_PADDING.', () => {
        expect(backend['padding']).toStrictEqual(crypto.constants.RSA_PKCS1_OAEP_PADDING);
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
          'The JSON Web Encryption Algorithm only accepts "RSA" JSON Web Keys.',
        );
      });

      it('should wrap the provided Content Encryption Key.', async () => {
        await expect(async () => (ek = await backend.wrap(cek, publicJwk, header))).resolves.not.toThrow();

        expect(ek).toBeInstanceOf(Buffer);
        expect(ek).toHaveLength(256);
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
          'The JSON Web Encryption Algorithm only accepts "RSA" JSON Web Keys.',
        );
      });

      it('should throw when the provided JSON Web Key is not a Private Key.', async () => {
        await expect(backend.unwrap(ek, publicJwk, header)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The provided JSON Web Key cannot be used to unwrap an Encrypted Key.',
        );
      });

      it('should throw when the provided Encrypted Key is invalid.', async () => {
        await expect(backend.unwrap(wrongEk, privateJwk, header)).rejects.toThrowWithMessage(
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

      it('should unwrap the provided Encrypted Key.', async () => {
        await expect(backend.unwrap(ek, privateJwk, header)).resolves.toStrictEqual(cek);
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
          'The JSON Web Encryption Algorithm only accepts "RSA" JSON Web Keys.',
        );
      });

      it('should generate a Content Encryption Key.', async () => {
        await expect(backend.generateContentEncryptionKey(publicJwk, header)).resolves.toStrictEqual(cek);
      });
    });
  });

  describe('RSA-OAEP-256', () => {
    const backend = new RSAESJsonWebEncryptionKeyManagementBackend('RSA-OAEP-256');

    const header = new JsonWebEncryptionHeader({ alg: 'RSA-OAEP-256', enc: 'A128GCM' });

    let ek!: Buffer;

    describe('hash', () => {
      it('should be "sha-256".', () => {
        expect(backend['hash']).toStrictEqual('sha-256');
      });
    });

    describe('padding', () => {
      it('should have the value of crypto.constants.RSA_PKCS1_OAEP_PADDING.', () => {
        expect(backend['padding']).toStrictEqual(crypto.constants.RSA_PKCS1_OAEP_PADDING);
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
          'The JSON Web Encryption Algorithm only accepts "RSA" JSON Web Keys.',
        );
      });

      it('should wrap the provided Content Encryption Key.', async () => {
        await expect(async () => (ek = await backend.wrap(cek, publicJwk, header))).resolves.not.toThrow();

        expect(ek).toBeInstanceOf(Buffer);
        expect(ek).toHaveLength(256);
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
          'The JSON Web Encryption Algorithm only accepts "RSA" JSON Web Keys.',
        );
      });

      it('should throw when the provided JSON Web Key is not a Private Key.', async () => {
        await expect(backend.unwrap(ek, publicJwk, header)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The provided JSON Web Key cannot be used to unwrap an Encrypted Key.',
        );
      });

      it('should throw when the provided Encrypted Key is invalid.', async () => {
        await expect(backend.unwrap(wrongEk, privateJwk, header)).rejects.toThrowWithMessage(
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

      it('should unwrap the provided Encrypted Key.', async () => {
        await expect(backend.unwrap(ek, privateJwk, header)).resolves.toStrictEqual(cek);
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
          'The JSON Web Encryption Algorithm only accepts "RSA" JSON Web Keys.',
        );
      });

      it('should generate a Content Encryption Key.', async () => {
        await expect(backend.generateContentEncryptionKey(publicJwk, header)).resolves.toStrictEqual(cek);
      });
    });
  });

  describe('RSA-OAEP-384', () => {
    const backend = new RSAESJsonWebEncryptionKeyManagementBackend('RSA-OAEP-384');

    const header = new JsonWebEncryptionHeader({ alg: 'RSA-OAEP-384', enc: 'A128GCM' });

    let ek!: Buffer;

    describe('hash', () => {
      it('should be "sha-384".', () => {
        expect(backend['hash']).toStrictEqual('sha-384');
      });
    });

    describe('padding', () => {
      it('should have the value of crypto.constants.RSA_PKCS1_OAEP_PADDING.', () => {
        expect(backend['padding']).toStrictEqual(crypto.constants.RSA_PKCS1_OAEP_PADDING);
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
          'The JSON Web Encryption Algorithm only accepts "RSA" JSON Web Keys.',
        );
      });

      it('should wrap the provided Content Encryption Key.', async () => {
        await expect(async () => (ek = await backend.wrap(cek, publicJwk, header))).resolves.not.toThrow();

        expect(ek).toBeInstanceOf(Buffer);
        expect(ek).toHaveLength(256);
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
          'The JSON Web Encryption Algorithm only accepts "RSA" JSON Web Keys.',
        );
      });

      it('should throw when the provided JSON Web Key is not a Private Key.', async () => {
        await expect(backend.unwrap(ek, publicJwk, header)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The provided JSON Web Key cannot be used to unwrap an Encrypted Key.',
        );
      });

      it('should throw when the provided Encrypted Key is invalid.', async () => {
        await expect(backend.unwrap(wrongEk, privateJwk, header)).rejects.toThrowWithMessage(
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

      it('should unwrap the provided Encrypted Key.', async () => {
        await expect(backend.unwrap(ek, privateJwk, header)).resolves.toStrictEqual(cek);
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
          'The JSON Web Encryption Algorithm only accepts "RSA" JSON Web Keys.',
        );
      });

      it('should generate a Content Encryption Key.', async () => {
        await expect(backend.generateContentEncryptionKey(publicJwk, header)).resolves.toStrictEqual(cek);
      });
    });
  });

  describe('RSA-OAEP-512', () => {
    const backend = new RSAESJsonWebEncryptionKeyManagementBackend('RSA-OAEP-512');

    const header = new JsonWebEncryptionHeader({ alg: 'RSA-OAEP-512', enc: 'A128GCM' });

    let ek!: Buffer;

    describe('hash', () => {
      it('should be "sha-512".', () => {
        expect(backend['hash']).toStrictEqual('sha-512');
      });
    });

    describe('padding', () => {
      it('should have the value of crypto.constants.RSA_PKCS1_OAEP_PADDING.', () => {
        expect(backend['padding']).toStrictEqual(crypto.constants.RSA_PKCS1_OAEP_PADDING);
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
          'The JSON Web Encryption Algorithm only accepts "RSA" JSON Web Keys.',
        );
      });

      it('should wrap the provided Content Encryption Key.', async () => {
        await expect(async () => (ek = await backend.wrap(cek, publicJwk, header))).resolves.not.toThrow();

        expect(ek).toBeInstanceOf(Buffer);
        expect(ek).toHaveLength(256);
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
          'The JSON Web Encryption Algorithm only accepts "RSA" JSON Web Keys.',
        );
      });

      it('should throw when the provided JSON Web Key is not a Private Key.', async () => {
        await expect(backend.unwrap(ek, publicJwk, header)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The provided JSON Web Key cannot be used to unwrap an Encrypted Key.',
        );
      });

      it('should throw when the provided Encrypted Key is invalid.', async () => {
        await expect(backend.unwrap(wrongEk, privateJwk, header)).rejects.toThrowWithMessage(
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

      it('should unwrap the provided Encrypted Key.', async () => {
        await expect(backend.unwrap(ek, privateJwk, header)).resolves.toStrictEqual(cek);
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
          'The JSON Web Encryption Algorithm only accepts "RSA" JSON Web Keys.',
        );
      });

      it('should generate a Content Encryption Key.', async () => {
        await expect(backend.generateContentEncryptionKey(publicJwk, header)).resolves.toStrictEqual(cek);
      });
    });
  });

  describe('RSA1_5', () => {
    const backend = new RSAESJsonWebEncryptionKeyManagementBackend('RSA1_5');

    const header = new JsonWebEncryptionHeader({ alg: 'RSA1_5', enc: 'A128GCM' });

    let ek!: Buffer;

    describe('hash', () => {
      it('should be undefined.', () => {
        expect(backend['hash']).toBeUndefined();
      });
    });

    describe('padding', () => {
      it('should have the value of crypto.constants.RSA_PKCS1_PADDING.', () => {
        expect(backend['padding']).toStrictEqual(crypto.constants.RSA_PKCS1_PADDING);
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
          'The JSON Web Encryption Algorithm only accepts "RSA" JSON Web Keys.',
        );
      });

      it('should wrap the provided Content Encryption Key.', async () => {
        await expect(async () => (ek = await backend.wrap(cek, publicJwk, header))).resolves.not.toThrow();

        expect(ek).toBeInstanceOf(Buffer);
        expect(ek).toHaveLength(256);
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
          'The JSON Web Encryption Algorithm only accepts "RSA" JSON Web Keys.',
        );
      });

      it('should throw when the provided JSON Web Key is not a Private Key.', async () => {
        await expect(backend.unwrap(ek, publicJwk, header)).rejects.toThrowWithMessage(
          InvalidJsonWebKeyError,
          'The provided JSON Web Key cannot be used to unwrap an Encrypted Key.',
        );
      });

      it('should unwrap the provided Encrypted Key.', async () => {
        await expect(backend.unwrap(ek, privateJwk, header)).resolves.toStrictEqual(cek);
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
          'The JSON Web Encryption Algorithm only accepts "RSA" JSON Web Keys.',
        );
      });

      it('should generate a Content Encryption Key.', async () => {
        await expect(backend.generateContentEncryptionKey(publicJwk, header)).resolves.toStrictEqual(cek);
      });
    });
  });
});
