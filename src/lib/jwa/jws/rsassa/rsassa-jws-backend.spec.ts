import { Buffer } from 'buffer';

import { InvalidJwsException } from '../../../exceptions/invalid-jws.exception';
import { RsaPrivateJwk } from '../../jwk/rsa/rsa-private-jwk';
import { RsaPublicJwk } from '../../jwk/rsa/rsa-public-jwk';
import { RsaSsaJwsBackend } from './rsassa-jws-backend';

const message = Buffer.from('Super secret message.');

const invalidHashes: any[] = [
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

const invalidRsaSsaPaddings: any[] = [
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

describe('RSASSA JWS Backend.', () => {
  let publicKey!: RsaPublicJwk;
  let privateKey!: RsaPrivateJwk;

  beforeEach(() => {
    publicKey = new RsaPublicJwk({
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

    privateKey = new RsaPrivateJwk({
      ...publicKey.toJSON(),
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
  });

  describe('constructor', () => {
    it.each(invalidHashes)('should throw when providing an unsupported rsassa padding.', (hash) => {
      expect(() => new RsaSsaJwsBackend(hash, 'RSASSA-PKCS1-v1_5')).toThrowWithMessage(
        TypeError,
        `Unsupported hash "${String(hash)}".`,
      );
    });

    it.each(invalidRsaSsaPaddings)('should throw when providing an unsupported rsassa padding.', (padding) => {
      expect(() => new RsaSsaJwsBackend('SHA256', padding)).toThrowWithMessage(
        TypeError,
        `Unsupported rsassa padding "${String(padding)}".`,
      );
    });
  });

  describe('RS256', () => {
    let signature!: Buffer;
    const backend = new RsaSsaJwsBackend('SHA256', 'RSASSA-PKCS1-v1_5');

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

  describe('RS384', () => {
    let signature!: Buffer;
    const backend = new RsaSsaJwsBackend('SHA384', 'RSASSA-PKCS1-v1_5');

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

  describe('RS512', () => {
    let signature!: Buffer;
    const backend = new RsaSsaJwsBackend('SHA512', 'RSASSA-PKCS1-v1_5');

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

  describe('PS256', () => {
    let signature!: Buffer;
    const backend = new RsaSsaJwsBackend('SHA256', 'RSASSA-PSS');

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

  describe('PS384', () => {
    let signature!: Buffer;
    const backend = new RsaSsaJwsBackend('SHA384', 'RSASSA-PSS');

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

  describe('PS512', () => {
    let signature!: Buffer;
    const backend = new RsaSsaJwsBackend('SHA512', 'RSASSA-PSS');

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
