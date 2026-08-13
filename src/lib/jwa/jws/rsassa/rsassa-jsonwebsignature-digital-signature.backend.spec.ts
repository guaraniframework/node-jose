import { Buffer } from 'buffer';
import crypto from 'crypto';

import { InvalidJsonWebKeyError } from '../../../errors/invalid-jsonwebkey.error';
import { InvalidJsonWebSignatureError } from '../../../errors/invalid-jsonwebsignature.error';
import { EllipticCurveJsonWebKey } from '../../jwk/ec/elliptic-curve.jsonwebkey';
import { RsaJsonWebKey } from '../../jwk/rsa/rsa.jsonwebkey';
import { RSASSAJsonWebSignatureDigitalSignatureBackend } from './rsassa-jsonwebsignature-digital-signature.backend';

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

describe('RSASSA JSON Web Signature Digital Signature Backend.', () => {
  const message = Buffer.from('Super secret message.', 'utf8');

  const publicJsonWebKey = new RsaJsonWebKey({
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

  const privateJsonWebKey = new RsaJsonWebKey({
    ...publicJsonWebKey.parameters,
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

  const wrongAlgJsonWebKey = new RsaJsonWebKey({
    kty: 'RSA',
    n:
      'xjpFydzTbByzL5jhEa2yQO63dpS9d9SKaN107AR69skKiTR4uK1c4SzDt4YcurDB' +
      'yhgKNzeBo6Vq3IRrkrltp97LKWfeZdM-leGt8-UTZEWqrNf3UGOEj8kI6lbjiG-S' +
      'n_yNHcVA9qBV22norZkgXctHLeFbY6TmpD-I8_UiplZUHoc9KlYc7crCQRa-O7tK' +
      'FDULNTMjjifc0dmuYP7ZcYAZXmRmoOpQuDr8s7OZY7TAqN0btMfA7RpUCWLT6TMR' +
      'QPX8GcyTxfbkOrSTFueKMHVNdXDtl068XXJ9mkjORiEmwlzqSBoxdeLWcNf_u20S' +
      '5JG5iK0nsm1uZYu-02XN-w',
    e: 'AQAB',
    alg: 'ECDH-ES',
  });

  const wrongKtyJsonWebKey = new EllipticCurveJsonWebKey({
    kty: 'EC',
    crv: 'P-256',
    x: '4c_cS6IT6jaVQeobt_6BDCTmzBaBOTmmiSCpjd5a6Og',
    y: 'mnrPnCFTDkGdEwilabaqM7DzwlAFgetZTmP9ycHPxF8',
    d: 'bwVX6Vx-TOfGKYOPAcu2xhaj3JUzs-McsC-suaHnFBo',
  });

  const wrongSignature = Buffer.from('APwj7CgHdXxQsdUFm-JpLib8ufFZMWM0JeG7OboIhKc', 'base64url');
  const wrongMessage = Buffer.from('Bad message.', 'utf8');

  const wrongJsonWebKey = new RsaJsonWebKey({
    kty: 'RSA',
    n:
      'oZ9ANo0w0XDqLw29D7ZM_Qd8fR-6B_3l-MZ0CLikkfz71ivN28vm8hR4FIQJZAzR' +
      'MdJXNDPVW3RG7ygCMVRgPl7IDAaU-ZIsowPoV63WePYZGd_x5MVdn9ZXzzSohw8u' +
      'oJHYFwIn_RAHWNjS8e9_PpT2I3LhBbzm4k5rGJS8j2N1OC0DyGVLAc5Bif2klH7x' +
      '-WPzFxqpCBLVfy9vQ1rtCo2Nwt9zlC1SLoiky7JxPwk3-4RuqRvUBhAZ_xyjbo68' +
      'k9rfkPW1JqV-27ZbXHOH4rf6zAlEFjWOnKJsWYIKJDBHN2et6EpVgH66rZb-_fqf' +
      'Kqx1xeZT-YlfVK0MtakHKw',
    e: 'AQAB',
  });

  describe('PS256', () => {
    const backend = new RSASSAJsonWebSignatureDigitalSignatureBackend('PS256');

    let signature!: Buffer;

    describe('padding', () => {
      it('should have the value of crypto.constants.RSA_PKCS1_PSS_PADDING.', () => {
        expect(backend['padding']).toStrictEqual(crypto.constants.RSA_PKCS1_PSS_PADDING);
      });
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
          'The JSON Web Signature Algorithm only accepts "RSA" JSON Web Keys.',
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
          'The JSON Web Signature Algorithm only accepts "RSA" JSON Web Keys.',
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

  describe('PS384', () => {
    const backend = new RSASSAJsonWebSignatureDigitalSignatureBackend('PS384');

    let signature!: Buffer;

    describe('padding', () => {
      it('should have the value of crypto.constants.RSA_PKCS1_PSS_PADDING.', () => {
        expect(backend['padding']).toStrictEqual(crypto.constants.RSA_PKCS1_PSS_PADDING);
      });
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
          'The JSON Web Signature Algorithm only accepts "RSA" JSON Web Keys.',
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
          'The JSON Web Signature Algorithm only accepts "RSA" JSON Web Keys.',
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

  describe('PS512', () => {
    const backend = new RSASSAJsonWebSignatureDigitalSignatureBackend('PS512');

    let signature!: Buffer;

    describe('padding', () => {
      it('should have the value of crypto.constants.RSA_PKCS1_PSS_PADDING.', () => {
        expect(backend['padding']).toStrictEqual(crypto.constants.RSA_PKCS1_PSS_PADDING);
      });
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
          'The JSON Web Signature Algorithm only accepts "RSA" JSON Web Keys.',
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
          'The JSON Web Signature Algorithm only accepts "RSA" JSON Web Keys.',
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

  describe('RS256', () => {
    const backend = new RSASSAJsonWebSignatureDigitalSignatureBackend('RS256');

    let signature!: Buffer;

    describe('padding', () => {
      it('should have the value of crypto.constants.RSA_PKCS1_PADDING.', () => {
        expect(backend['padding']).toStrictEqual(crypto.constants.RSA_PKCS1_PADDING);
      });
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
          'The JSON Web Signature Algorithm only accepts "RSA" JSON Web Keys.',
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
          'The JSON Web Signature Algorithm only accepts "RSA" JSON Web Keys.',
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

  describe('RS384', () => {
    const backend = new RSASSAJsonWebSignatureDigitalSignatureBackend('RS384');

    let signature!: Buffer;

    describe('padding', () => {
      it('should have the value of crypto.constants.RSA_PKCS1_PADDING.', () => {
        expect(backend['padding']).toStrictEqual(crypto.constants.RSA_PKCS1_PADDING);
      });
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
          'The JSON Web Signature Algorithm only accepts "RSA" JSON Web Keys.',
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
          'The JSON Web Signature Algorithm only accepts "RSA" JSON Web Keys.',
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

  describe('RS512', () => {
    const backend = new RSASSAJsonWebSignatureDigitalSignatureBackend('RS512');

    let signature!: Buffer;

    describe('padding', () => {
      it('should have the value of crypto.constants.RSA_PKCS1_PADDING.', () => {
        expect(backend['padding']).toStrictEqual(crypto.constants.RSA_PKCS1_PADDING);
      });
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
          'The JSON Web Signature Algorithm only accepts "RSA" JSON Web Keys.',
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
          'The JSON Web Signature Algorithm only accepts "RSA" JSON Web Keys.',
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
