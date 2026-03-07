import { Buffer } from 'buffer';

import { InvalidJwkException } from '../../exceptions/invalid-jwk.exception';
import { RsaPublicJwk } from '../jwk/rsa/rsa-public-jwk';
import { JwsBackend } from './jws-backend';

const invalidArgs: any[] = [
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

const key = new RsaPublicJwk({
  kty: 'RSA',
  n:
    'oZ9ANo0w0XDqLw29D7ZM_Qd8fR-6B_3l-MZ0CLikkfz71ivN28vm8hR4FIQJZAzR' +
    'MdJXNDPVW3RG7ygCMVRgPl7IDAaU-ZIsowPoV63WePYZGd_x5MVdn9ZXzzSohw8u' +
    'oJHYFwIn_RAHWNjS8e9_PpT2I3LhBbzm4k5rGJS8j2N1OC0DyGVLAc5Bif2klH7x' +
    '-WPzFxqpCBLVfy9vQ1rtCo2Nwt9zlC1SLoiky7JxPwk3-4RuqRvUBhAZ_xyjbo68' +
    'k9rfkPW1JqV-27ZbXHOH4rf6zAlEFjWOnKJsWYIKJDBHN2et6EpVgH66rZb-_fqf' +
    'Kqx1xeZT-YlfVK0MtakHKw',
  e: 'AQAB',
  alg: 'RS256',
});

describe('JWS Backend', () => {
  let backend!: JwsBackend;

  beforeEach(() => {
    backend = Reflect.construct(JwsBackend, ['RS256']);
  });

  describe('validateJwk()', () => {
    it.each(invalidArgs)('should throw when not providing a jwk.', (arg) => {
      expect(() => backend['validateJwk'](arg)).toThrowWithMessage(TypeError, 'Invalid jwk.');
    });

    it('should throw when the jwk kty does not match the kty expected by the jws backend.', () => {
      Reflect.set(backend, 'alg', 'ES256');
      Reflect.set(backend, 'kty', 'EC');

      expect(() => backend['validateJwk'](key)).toThrowWithMessage(
        InvalidJwkException,
        'The jws algorithm "ES256" only accepts "EC" jwk keys.',
      );
    });

    it('should throw when the jwk alg does not match the alg expected by the jws backend.', () => {
      Reflect.set(backend, 'alg', 'RS512');
      Reflect.set(backend, 'kty', 'RSA');

      expect(() => backend['validateJwk'](key)).toThrowWithMessage(
        InvalidJwkException,
        'This jwk is intended to be used by the jws algorithm "RS512".',
      );
    });

    it('should not throw when the provided key can be used by the jws algorithm.', () => {
      Reflect.set(backend, 'kty', 'RSA');

      expect(() => backend['validateJwk'](key)).not.toThrow();
    });
  });
});
