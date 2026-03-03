import { Buffer } from 'buffer';
import http from 'http';
import https from 'https';
import Stream from 'stream';

import { InvalidJoseHeaderException } from '../exceptions/invalid-jose-header.exception';
import { JwkParams } from '../jwk/jwk.params';
import { JoseHeader } from './jose-header';
import { JoseHeaderParams } from './jose-header.params';

const invalidArgs: any[] = [null, true, 1, 1.2, 1n, 'a', Symbol('a'), Buffer, Buffer.alloc(1), () => 1, []];
const invalidAlgs: any[] = [null, true, 1, 1.2, 1n, Symbol('a'), Buffer, Buffer.alloc(1), () => 1, {}, [], 'a'];
const invalidJkus: any[] = [null, true, 1, 1.2, 1n, Symbol('a'), Buffer, Buffer.alloc(1), () => 1, {}, [], 'a'];
const invalidJwks: any[] = [null, true, 1, 1.2, 1n, 'a', Symbol('a'), Buffer, Buffer.alloc(1), () => 1, []];
const invalidKids: any[] = [null, true, 1, 1.2, 1n, Symbol('a'), Buffer, Buffer.alloc(1), () => 1, {}, []];
const invalidX5Us: any[] = [null, true, 1, 1.2, 1n, Symbol('a'), Buffer, Buffer.alloc(1), () => 1, {}, [], 'a'];

const invalidX5Cs: any[] = [
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
  [null],
  [true],
  [1],
  [1.2],
  [1n],
  [Symbol('a')],
  [Buffer],
  [Buffer.alloc(1)],
  [() => 1],
  [{}],
  [[]],
];

const invalidX5Ts: any[] = [null, true, 1, 1.2, 1n, Symbol('a'), Buffer, Buffer.alloc(1), () => 1, {}, []];
const invalidX5TS256s: any[] = [null, true, 1, 1.2, 1n, Symbol('a'), Buffer, Buffer.alloc(1), () => 1, {}, []];
const invalidTyps: any[] = [null, true, 1, 1.2, 1n, Symbol('a'), Buffer, Buffer.alloc(1), () => 1, {}, []];
const invalidCtys: any[] = [null, true, 1, 1.2, 1n, Symbol('a'), Buffer, Buffer.alloc(1), () => 1, {}, []];
const invalidCrits: any[] = [
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
  [null],
  [true],
  [1],
  [1.2],
  [1n],
  [Symbol('a')],
  [Buffer],
  [Buffer.alloc(1)],
  [() => 1],
  [{}],
  [[]],
  [''],
];

const invalidDatas: any[] = [null, true, 1, 1.2, 1n, 'a', Symbol('a'), Buffer, Buffer.alloc(1), () => 1, [], {}];

const jwk: JwkParams = {
  kty: 'RSA',
  n:
    'oZ9ANo0w0XDqLw29D7ZM_Qd8fR-6B_3l-MZ0CLikkfz71ivN28vm8hR4FIQJZAzR' +
    'MdJXNDPVW3RG7ygCMVRgPl7IDAaU-ZIsowPoV63WePYZGd_x5MVdn9ZXzzSohw8u' +
    'oJHYFwIn_RAHWNjS8e9_PpT2I3LhBbzm4k5rGJS8j2N1OC0DyGVLAc5Bif2klH7x' +
    '-WPzFxqpCBLVfy9vQ1rtCo2Nwt9zlC1SLoiky7JxPwk3-4RuqRvUBhAZ_xyjbo68' +
    'k9rfkPW1JqV-27ZbXHOH4rf6zAlEFjWOnKJsWYIKJDBHN2et6EpVgH66rZb-_fqf' +
    'Kqx1xeZT-YlfVK0MtakHKw',
  e: 'AQAB',
};

const x5c: string[] = [
  'MIIDBjCCAe6gAwIBAgIUfGXBlyYZdDvo6NWkapYYyZJCkNwwDQYJKoZIhvcNAQEL' +
    'BQAwIzEhMB8GA1UEAwwYUmV2ZW5za3kgSW50ZXJtZWRpYXRlIENBMB4XDTI2MDIy' +
    'NzE5NDkwN1oXDTI3MDIyNzE5NDkwN1owEzERMA8GA1UEAwwIUmV2ZW5za3kwggEi' +
    'MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQChn0A2jTDRcOovDb0Ptkz9B3x9' +
    'H7oH/eX4xnQIuKSR/PvWK83by+byFHgUhAlkDNEx0lc0M9VbdEbvKAIxVGA+XsgM' +
    'BpT5kiyjA+hXrdZ49hkZ3/HkxV2f1lfPNKiHDy6gkdgXAif9EAdY2NLx738+lPYj' +
    'cuEFvObiTmsYlLyPY3U4LQPIZUsBzkGJ/aSUfvH5Y/MXGqkIEtV/L29DWu0KjY3C' +
    '33OULVIuiKTLsnE/CTf7hG6pG9QGEBn/HKNujryT2t+Q9bUmpX7btltcc4fit/rM' +
    'CUQWNY6comxZggokMEc3Z63oSlWAfrqtlv79+p8qrHXF5lP5iV9UrQy1qQcrAgMB' +
    'AAGjQjBAMB0GA1UdDgQWBBRkNTEtKpoT13zSSmmklu5TToxx2DAfBgNVHSMEGDAW' +
    'gBTSjEMShDHN1LVx8GjgR/DOAgMxFDANBgkqhkiG9w0BAQsFAAOCAQEARrcDkPHu' +
    'DVBNpvWLsh3052vt9Wg9twmPUFFoDgdob9j0hpSoqeYzf/ztHjnCcAUr48gKFJMI' +
    '7BxRbi9No8JaAOtbq1aGr53Ozd0hSATef3aP4p5NsIWrXxC26VTMW+kjo3YKwVdR' +
    'pyz2DKSN7RBUhmO0X0YCvo7P88yDtOBQyKlsqI7mLyv7WX1mJ2Y/zvvK14RLt17Z' +
    'A9YojROLhyZUVv+4hFALwZugNSZqKCE8VS7XA13zVE/hC7IyzjIPoutjbEuj5Abb' +
    'WINOOIchBLxly2TCzE/kkrZ8uPOEghR71os9L+u6oYu+q4jh9LY2D9nHSg5y1jkq' +
    '3NJ5yD2vzvXZ2Q==',
  'MIIDCTCCAfGgAwIBAgIULim7Ch5k1Ut89QZvejuclYahzcMwDQYJKoZIhvcNAQEL' +
    'BQAwFjEUMBIGA1UEAwwLUmV2ZW5za3kgQ0EwHhcNMjYwMjI3MTk0ODM1WhcNMjcw' +
    'MjI3MTk0ODM1WjAjMSEwHwYDVQQDDBhSZXZlbnNreSBJbnRlcm1lZGlhdGUgQ0Ew' +
    'ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDKdCihPzetkTXTROiqNonp' +
    '/uFhuk0Nm1DgZo230aVWN8paNuuXxKkzXyESROJtb+AaTvYPamfs9L97EF93hFZ+' +
    'A7+8lDRx9FGNhU9y1ambaTo8COXr0FtktmtPNtWG6BeHojuMHzkY6YWaGqi/FhM4' +
    'xr6TKsXqC4TTzdtShl96qXrJySmCtAIjlMRRqn4skz6oJ8JVMDeOCg0/73zy942O' +
    '210+/91+ONnmPwbDZvz+UkEj/yMD0dE90dYWUEhltoU8A5gVOzVHVxd0/HCvVBIB' +
    'kfdU9YtxykoTBG+5puQOBZTORLG/mKKeHj4LX4mrid7zehL8NkXMPX9f5kbQ3WWB' +
    'AgMBAAGjQjBAMB0GA1UdDgQWBBTSjEMShDHN1LVx8GjgR/DOAgMxFDAfBgNVHSME' +
    'GDAWgBSi8AliI6vKZPBIsVfHYPCba32i0zANBgkqhkiG9w0BAQsFAAOCAQEAZaH/' +
    'ZIPa7GA3RqrF10cDFePFkZIPfLKzcHXko4DhaaJZlGxnOwJ+bZN4q7TOBe/qyknv' +
    'oMPfZrjxK05wM7CjYBWdK8n4rIsPmcxzVEMCbHNSET+Pf1y3yehdIk1e/cY82puz' +
    'eBYIbu2Axl2qvKJTeFASl0Wq51nJ1GTLMvaOFiP5q1YXKZhDRjMW/8d/HDerDNYw' +
    'lPwxFUpDiUSiMxR7HG46rTTv+hiJEPh+etQi15oxDYLoTaXP90Z5m43DnndgSR5e' +
    'UEhmK4x1z1RSeTKmJg3mmMcXkuO0Xa2UE8++NANzcysfOoTMKl+3V7N4QSFuGEW3' +
    'y13j5RKviQ3smEdBvA==',
  'MIIDDTCCAfWgAwIBAgIUGAy8oskSYRmqzuIb1/PNUBU0KEEwDQYJKoZIhvcNAQEL' +
    'BQAwFjEUMBIGA1UEAwwLUmV2ZW5za3kgQ0EwHhcNMjYwMjI3MTk0NzMxWhcNMjcw' +
    'MjI3MTk0NzMxWjAWMRQwEgYDVQQDDAtSZXZlbnNreSBDQTCCASIwDQYJKoZIhvcN' +
    'AQEBBQADggEPADCCAQoCggEBAKsCpcaP9+s0EeNWdZUBO5o2ujDTjVWjGHtf0z2O' +
    '/4nfXPnQdmKNQbF0zQLPbkAKyinN5uwJjcQE33eybR4VPyFVpKDE6ytAmgFNG9+R' +
    '9fmcvhaTsN6uzenl8Us5uR+BpIHsLSa/6EYT2vTgBSbbG7W644IZnTR2dQ70iSJv' +
    'gMw+hGQuBLCjZk6ElN1Y3z4ygeTyVSgoKPeCCUO+uGKhk7rJ01LrhvUFSqO6prjE' +
    'UnM9qnfAvI3BgHX6aItVdYDIZxx+ybinyl/JcV8URDjxbytj1G5UEHNCuRc+pjzt' +
    'gBRsZNed+11Z0sGO4zJMwcHDNwNRRAw+VABmoIIHgcxtR7cCAwEAAaNTMFEwHQYD' +
    'VR0OBBYEFKLwCWIjq8pk8EixV8dg8JtrfaLTMB8GA1UdIwQYMBaAFKLwCWIjq8pk' +
    '8EixV8dg8JtrfaLTMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEB' +
    'AEb2ad6R150bFvh++1csVg2pJBJhVvkDVLw1VSW10L4WW339wgrtmlWeBMlcFFJ9' +
    'j++9HTtce5OB0dIytG8D/E0w6SUcMFpYL6pa4mIx54oZGe2l7iwSGS/NSfnGrcP1' +
    'Z8IsW5C+jThFR3RStHul4/soA9rgroNcvCNaiibiUpBlz5S8f0d8KkEHlwmNsAZv' +
    '4JmECqRPQRk2N6ZqtOhwFAZskyLOF9kreD4CdFKxucCc9jv2UIUtlR9X9IsGsrV2' +
    'R95IzriYmlniFv98U6m+Q8JGGnBcj0caVsxUqIp2oqGi3oUMoYWBekY52ELzKxLd' +
    '/p0IrAZpxzqzw3OqXnCSvZk=',
];

const pemCertChain: string = `-----BEGIN CERTIFICATE-----
MIIDBjCCAe6gAwIBAgIUfGXBlyYZdDvo6NWkapYYyZJCkNwwDQYJKoZIhvcNAQEL
BQAwIzEhMB8GA1UEAwwYUmV2ZW5za3kgSW50ZXJtZWRpYXRlIENBMB4XDTI2MDIy
NzE5NDkwN1oXDTI3MDIyNzE5NDkwN1owEzERMA8GA1UEAwwIUmV2ZW5za3kwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQChn0A2jTDRcOovDb0Ptkz9B3x9
H7oH/eX4xnQIuKSR/PvWK83by+byFHgUhAlkDNEx0lc0M9VbdEbvKAIxVGA+XsgM
BpT5kiyjA+hXrdZ49hkZ3/HkxV2f1lfPNKiHDy6gkdgXAif9EAdY2NLx738+lPYj
cuEFvObiTmsYlLyPY3U4LQPIZUsBzkGJ/aSUfvH5Y/MXGqkIEtV/L29DWu0KjY3C
33OULVIuiKTLsnE/CTf7hG6pG9QGEBn/HKNujryT2t+Q9bUmpX7btltcc4fit/rM
CUQWNY6comxZggokMEc3Z63oSlWAfrqtlv79+p8qrHXF5lP5iV9UrQy1qQcrAgMB
AAGjQjBAMB0GA1UdDgQWBBRkNTEtKpoT13zSSmmklu5TToxx2DAfBgNVHSMEGDAW
gBTSjEMShDHN1LVx8GjgR/DOAgMxFDANBgkqhkiG9w0BAQsFAAOCAQEARrcDkPHu
DVBNpvWLsh3052vt9Wg9twmPUFFoDgdob9j0hpSoqeYzf/ztHjnCcAUr48gKFJMI
7BxRbi9No8JaAOtbq1aGr53Ozd0hSATef3aP4p5NsIWrXxC26VTMW+kjo3YKwVdR
pyz2DKSN7RBUhmO0X0YCvo7P88yDtOBQyKlsqI7mLyv7WX1mJ2Y/zvvK14RLt17Z
A9YojROLhyZUVv+4hFALwZugNSZqKCE8VS7XA13zVE/hC7IyzjIPoutjbEuj5Abb
WINOOIchBLxly2TCzE/kkrZ8uPOEghR71os9L+u6oYu+q4jh9LY2D9nHSg5y1jkq
3NJ5yD2vzvXZ2Q==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDCTCCAfGgAwIBAgIULim7Ch5k1Ut89QZvejuclYahzcMwDQYJKoZIhvcNAQEL
BQAwFjEUMBIGA1UEAwwLUmV2ZW5za3kgQ0EwHhcNMjYwMjI3MTk0ODM1WhcNMjcw
MjI3MTk0ODM1WjAjMSEwHwYDVQQDDBhSZXZlbnNreSBJbnRlcm1lZGlhdGUgQ0Ew
ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDKdCihPzetkTXTROiqNonp
/uFhuk0Nm1DgZo230aVWN8paNuuXxKkzXyESROJtb+AaTvYPamfs9L97EF93hFZ+
A7+8lDRx9FGNhU9y1ambaTo8COXr0FtktmtPNtWG6BeHojuMHzkY6YWaGqi/FhM4
xr6TKsXqC4TTzdtShl96qXrJySmCtAIjlMRRqn4skz6oJ8JVMDeOCg0/73zy942O
210+/91+ONnmPwbDZvz+UkEj/yMD0dE90dYWUEhltoU8A5gVOzVHVxd0/HCvVBIB
kfdU9YtxykoTBG+5puQOBZTORLG/mKKeHj4LX4mrid7zehL8NkXMPX9f5kbQ3WWB
AgMBAAGjQjBAMB0GA1UdDgQWBBTSjEMShDHN1LVx8GjgR/DOAgMxFDAfBgNVHSME
GDAWgBSi8AliI6vKZPBIsVfHYPCba32i0zANBgkqhkiG9w0BAQsFAAOCAQEAZaH/
ZIPa7GA3RqrF10cDFePFkZIPfLKzcHXko4DhaaJZlGxnOwJ+bZN4q7TOBe/qyknv
oMPfZrjxK05wM7CjYBWdK8n4rIsPmcxzVEMCbHNSET+Pf1y3yehdIk1e/cY82puz
eBYIbu2Axl2qvKJTeFASl0Wq51nJ1GTLMvaOFiP5q1YXKZhDRjMW/8d/HDerDNYw
lPwxFUpDiUSiMxR7HG46rTTv+hiJEPh+etQi15oxDYLoTaXP90Z5m43DnndgSR5e
UEhmK4x1z1RSeTKmJg3mmMcXkuO0Xa2UE8++NANzcysfOoTMKl+3V7N4QSFuGEW3
y13j5RKviQ3smEdBvA==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDDTCCAfWgAwIBAgIUGAy8oskSYRmqzuIb1/PNUBU0KEEwDQYJKoZIhvcNAQEL
BQAwFjEUMBIGA1UEAwwLUmV2ZW5za3kgQ0EwHhcNMjYwMjI3MTk0NzMxWhcNMjcw
MjI3MTk0NzMxWjAWMRQwEgYDVQQDDAtSZXZlbnNreSBDQTCCASIwDQYJKoZIhvcN
AQEBBQADggEPADCCAQoCggEBAKsCpcaP9+s0EeNWdZUBO5o2ujDTjVWjGHtf0z2O
/4nfXPnQdmKNQbF0zQLPbkAKyinN5uwJjcQE33eybR4VPyFVpKDE6ytAmgFNG9+R
9fmcvhaTsN6uzenl8Us5uR+BpIHsLSa/6EYT2vTgBSbbG7W644IZnTR2dQ70iSJv
gMw+hGQuBLCjZk6ElN1Y3z4ygeTyVSgoKPeCCUO+uGKhk7rJ01LrhvUFSqO6prjE
UnM9qnfAvI3BgHX6aItVdYDIZxx+ybinyl/JcV8URDjxbytj1G5UEHNCuRc+pjzt
gBRsZNed+11Z0sGO4zJMwcHDNwNRRAw+VABmoIIHgcxtR7cCAwEAAaNTMFEwHQYD
VR0OBBYEFKLwCWIjq8pk8EixV8dg8JtrfaLTMB8GA1UdIwQYMBaAFKLwCWIjq8pk
8EixV8dg8JtrfaLTMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEB
AEb2ad6R150bFvh++1csVg2pJBJhVvkDVLw1VSW10L4WW339wgrtmlWeBMlcFFJ9
j++9HTtce5OB0dIytG8D/E0w6SUcMFpYL6pa4mIx54oZGe2l7iwSGS/NSfnGrcP1
Z8IsW5C+jThFR3RStHul4/soA9rgroNcvCNaiibiUpBlz5S8f0d8KkEHlwmNsAZv
4JmECqRPQRk2N6ZqtOhwFAZskyLOF9kreD4CdFKxucCc9jv2UIUtlR9X9IsGsrV2
R95IzriYmlniFv98U6m+Q8JGGnBcj0caVsxUqIp2oqGi3oUMoYWBekY52ELzKxLd
/p0IrAZpxzqzw3OqXnCSvZk=
-----END CERTIFICATE-----
`;

describe('Jose Header', () => {
  beforeAll(() => {
    jest.useFakeTimers();
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  describe('constructor', () => {
    it.each(invalidArgs)('should throw when the provided params is invalid.', (arg) => {
      expect(() => Reflect.construct(JoseHeader, [arg])).toThrowWithMessage(TypeError, 'Invalid parameter "params".');
    });

    it.each(invalidAlgs)('should throw when the provided "alg" is invalid.', (alg) => {
      expect(() => Reflect.construct(JoseHeader, [{ alg }])).toThrowWithMessage(
        InvalidJoseHeaderException,
        'Invalid jose header parameter "alg".',
      );
    });

    it.each(invalidJkus)('should throw when the provided "jku" is invalid.', (jku) => {
      expect(() => Reflect.construct(JoseHeader, [{ alg: 'RS256', jku }])).toThrowWithMessage(
        InvalidJoseHeaderException,
        'Invalid jose header parameter "jku".',
      );
    });

    it.each(invalidJwks)('should throw when the provided "jwk" is invalid.', (jwk) => {
      expect(() => Reflect.construct(JoseHeader, [{ alg: 'RS256', jwk }])).toThrowWithMessage(
        InvalidJoseHeaderException,
        'Invalid jose header parameter "jwk".',
      );
    });

    it('should throw when providing both "jku" and "jwk".', () => {
      expect(() =>
        Reflect.construct(JoseHeader, [
          { alg: 'RS256', jku: 'http://jwks-url.com', jwk: { kty: 'oct', k: 'secretkey' } },
        ]),
      ).toThrowWithMessage(InvalidJoseHeaderException, 'Cannot have both "jku" and "jwk" jose header parameters.');
    });

    it.each(invalidKids)('should throw when the provided "kid" is invalid.', (kid) => {
      expect(() => Reflect.construct(JoseHeader, [{ alg: 'RS256', kid }])).toThrowWithMessage(
        InvalidJoseHeaderException,
        'Invalid jose header parameter "kid".',
      );
    });

    it('should throw when providing the "jku" parameter and not providing the "kid" parameter.', () => {
      expect(() => Reflect.construct(JoseHeader, [{ alg: 'RS256', jku: 'http://jwks-url.com' }])).toThrowWithMessage(
        InvalidJoseHeaderException,
        'Missing jose header parameter "kid" when providing "jku".',
      );
    });

    it('should throw when getting an error while calling the jwks url.', () => {
      const stream = new Stream();

      https.get = jest.fn().mockImplementationOnce((_, cb) => {
        cb(stream);
        stream.emit('data', 'aabbccddeeff');
        stream.emit('error', new Error('HTTP Error.'));
      });

      expect(() =>
        Reflect.construct(JoseHeader, [{ alg: 'RS256', jku: 'https://jwks-url.com', kid: 'keyid' }]),
      ).toThrowWithMessage(InvalidJoseHeaderException, 'Error reading the jwks from the url.');
    });

    it('should throw when the jwks url returns an invalid jwks.', () => {
      const stream = new Stream();

      http.get = jest.fn().mockImplementationOnce((_, cb) => {
        cb(stream);
        stream.emit('data', 'aabbccddeeff');
        stream.emit('end');
      });

      expect(() =>
        Reflect.construct(JoseHeader, [{ alg: 'RS256', jku: 'http://jwks-url.com', kid: 'keyid' }]),
      ).toThrowWithMessage(InvalidJoseHeaderException, 'Invalid jku url.');
    });

    it('should throw when the jwks does not contain the requested key id.', () => {
      const stream = new Stream();

      http.get = jest.fn().mockImplementationOnce((_, cb) => {
        cb(stream);
        stream.emit('data', '{"keys":[{"kty":"oct","k":"secretkey","kid":"otherkeyid"}]}');
        stream.emit('end');
      });

      expect(() =>
        Reflect.construct(JoseHeader, [{ alg: 'RS256', jku: 'http://jwks-url.com', kid: 'keyid' }]),
      ).toThrowWithMessage(InvalidJoseHeaderException, 'Could not find the jwk "keyid" in the jwks.');
    });

    it('should throw when the provided jwk is invalid.', () => {
      expect(() => Reflect.construct(JoseHeader, [{ alg: 'RS256', jwk: { kty: 'unknown' } }])).toThrowWithMessage(
        InvalidJoseHeaderException,
        'The jwk provided in the jose header is invalid.',
      );
    });

    it('should throw when the parameter "kid" does not match the parameter "jwk.kid".', () => {
      expect(() =>
        Reflect.construct(JoseHeader, [
          { alg: 'RS256', jwk: { kty: 'oct', k: 'secretkey', kid: 'otherkeyid' }, kid: 'keyid' },
        ]),
      ).toThrowWithMessage(InvalidJoseHeaderException, 'Mismatching jose header parameter "kid" and "jwk.kid".');
    });

    it('should throw when providing a certificate thumbprint without a certificate chain.', () => {
      expect(() => Reflect.construct(JoseHeader, [{ alg: 'RS256', x5t: 'thumbprint' }])).toThrowWithMessage(
        InvalidJoseHeaderException,
        'Cannot have a certificate thumbprint without a certificate chain.',
      );

      expect(() => Reflect.construct(JoseHeader, [{ alg: 'RS256', 'x5t#S256': 'thumbprint' }])).toThrowWithMessage(
        InvalidJoseHeaderException,
        'Cannot have a certificate thumbprint without a certificate chain.',
      );
    });

    it('should throw when providing a certificate chain but not providing a jwk.', () => {
      expect(() => Reflect.construct(JoseHeader, [{ alg: 'RS256', x5c: pemCertChain }])).toThrowWithMessage(
        InvalidJoseHeaderException,
        'Missing jwk for the provided certificate chain.',
      );
    });

    it('should throw when providing both "x5u" and "x5c".', () => {
      expect(() =>
        Reflect.construct(JoseHeader, [{ alg: 'RS256', jwk, x5u: 'http://cert-url.com', x5c: ['certificate'] }]),
      ).toThrowWithMessage(InvalidJoseHeaderException, 'Cannot have both "x5u" and "x5c" jose header parameters.');
    });

    it.each(invalidX5Us)('should throw when the provided "x5u" is invalid.', (x5u) => {
      expect(() => Reflect.construct(JoseHeader, [{ alg: 'RS256', jwk, x5u }])).toThrowWithMessage(
        InvalidJoseHeaderException,
        'Invalid jose header parameter "x5u".',
      );
    });

    it('should throw when the jose header parameter "x5u" does not match the key parameter "x5u".', () => {
      const stream = new Stream();

      http.get = jest.fn().mockImplementationOnce((_, cb) => {
        cb(stream);
        pemCertChain.split('\n').forEach((chunk) => stream.emit('data', chunk));
        stream.emit('end');
      });

      expect(() =>
        Reflect.construct(JoseHeader, [
          { alg: 'RS256', jwk: { ...jwk, x5u: 'http://certificate-url.com' }, x5u: 'http://cert-url.com' },
        ]),
      ).toThrowWithMessage(InvalidJoseHeaderException, 'Invalid jose header parameter "x5u".');
    });

    it.each(invalidX5Cs)('should throw when the provided "x5c" is invalid.', (x5c) => {
      expect(() => Reflect.construct(JoseHeader, [{ alg: 'RS256', jwk, x5c }])).toThrowWithMessage(
        InvalidJoseHeaderException,
        'Invalid jose header parameter "x5c".',
      );
    });

    it('should throw when the jose header parameter "x5c" does not match the key parameter "x5c".', () => {
      expect(() =>
        Reflect.construct(JoseHeader, [{ alg: 'RS256', jwk: { ...jwk, x5c: [x5c[0], x5c[1]] }, x5c }]),
      ).toThrowWithMessage(InvalidJoseHeaderException, 'Invalid jose header parameter "x5c".');
    });

    it.each(invalidX5Ts)('should throw when the provided "x5t" is invalid.', (x5t) => {
      expect(() =>
        Reflect.construct(JoseHeader, [{ alg: 'RS256', jwk, x5u: 'http://cert-url.com', x5t }]),
      ).toThrowWithMessage(InvalidJoseHeaderException, 'Invalid jose header parameter "x5t".');
    });

    // TODO: Fix fingerprint format.
    it('should throw when the jose header parameter "x5t" does not match the key parameter "x5t".', () => {
      expect(() =>
        Reflect.construct(JoseHeader, [
          {
            alg: 'RS256',
            jwk: { ...jwk, x5c, x5t: 'B4:A2:FA:07:8B:09:1A:06:95:96:11:84:53:07:21:10:E2:53:03:9D' },
            x5c,
            x5t: 'thumb0',
          },
        ]),
      ).toThrowWithMessage(InvalidJoseHeaderException, 'Invalid jose header parameter "x5t".');
    });

    it.each(invalidX5TS256s)('should throw when the provided "x5t#S256" is invalid.', (x5tS256) => {
      expect(() =>
        Reflect.construct(JoseHeader, [{ alg: 'RS256', jwk, x5u: 'http://cert-url.com', 'x5t#S256': x5tS256 }]),
      ).toThrowWithMessage(InvalidJoseHeaderException, 'Invalid jose header parameter "x5t#S256".');
    });

    // TODO: Fix fingerprint format.
    it('should throw when the jose header parameter "x5t#S256" does not match the key parameter "x5t#S256".', () => {
      expect(() =>
        Reflect.construct(JoseHeader, [
          {
            alg: 'RS256',
            jwk: {
              ...jwk,
              x5c,
              'x5t#S256':
                '85:16:0E:71:47:C9:2E:1F:8C:77:A2:B3:68:E4:DD:93:D9:6F:F1:0F:25:86:F6:61:EA:E7:08:A9:DD:C6:68:6D',
            },
            x5c,
            'x5t#S256': 'thumb0',
          },
        ]),
      ).toThrowWithMessage(InvalidJoseHeaderException, 'Invalid jose header parameter "x5t#S256".');
    });

    it('should throw when providing an invalid x.509 certificate.', () => {
      expect(() => Reflect.construct(JoseHeader, [{ alg: 'RS256', jwk, x5c: ['aabbccddeeff'] }])).toThrowWithMessage(
        InvalidJoseHeaderException,
        'One or more certificates are invalid.',
      );
    });

    it('should throw when one or more x.509 certificates are not yet valid.', () => {
      jest.useFakeTimers({ now: new Date(2024, 0, 1, 0, 0, 0, 0) });

      expect(() => Reflect.construct(JoseHeader, [{ alg: 'RS256', jwk, x5c }])).toThrowWithMessage(
        InvalidJoseHeaderException,
        'One or more certificates are not yet valid.',
      );
    });

    it('should throw when one or more x.509 certificates are expired.', () => {
      jest.useFakeTimers({ now: new Date(2028, 0, 1, 0, 0, 0, 0) });

      expect(() => Reflect.construct(JoseHeader, [{ alg: 'RS256', jwk, x5c }])).toThrowWithMessage(
        InvalidJoseHeaderException,
        'One or more certificates are expired.',
      );
    });

    it('should throw when the first x.509 certificate does not match the public key.', () => {
      jest.useFakeTimers({ now: new Date(2026, 7, 12, 0, 0, 0, 0) });

      expect(() =>
        Reflect.construct(JoseHeader, [{ alg: 'RS256', jwk: { ...jwk, e: 'AQAA' }, x5c }]),
      ).toThrowWithMessage(InvalidJoseHeaderException, 'The provided certificate does not match the jwk.');
    });

    it('should throw when one or more x.509 certificates were not signed by a x.509 certificate in the chain.', () => {
      expect(() => Reflect.construct(JoseHeader, [{ alg: 'RS256', jwk, x5c: [x5c[0], x5c[2]] }])).toThrowWithMessage(
        InvalidJoseHeaderException,
        'Invalid certificate chain.',
      );
    });

    it('should throw when getting an error while calling the certificate url.', () => {
      const stream = new Stream();

      https.get = jest.fn().mockImplementationOnce((_, cb) => {
        cb(stream);
        stream.emit('data', 'aabbccddeeff');
        stream.emit('error', new Error('HTTP Error.'));
      });

      expect(() =>
        Reflect.construct(JoseHeader, [{ alg: 'RS256', jwk, x5u: 'https://cert-url.com' }]),
      ).toThrowWithMessage(InvalidJoseHeaderException, 'Error reading the certificate chain from the url.');
    });

    it('should throw when the certificate url returns an invalid certificate chain.', () => {
      const stream = new Stream();

      http.get = jest.fn().mockImplementationOnce((_, cb) => {
        cb(stream);
        stream.emit('data', 'aabbccddeeff');
        stream.emit('end');
      });

      expect(() =>
        Reflect.construct(JoseHeader, [{ alg: 'RS256', jwk, x5u: 'http://cert-url.com' }]),
      ).toThrowWithMessage(InvalidJoseHeaderException, 'Invalid X.509 URL.');
    });

    it('should throw when the provided "x5t" does not match the sha-1 fingerprint of the certificate.', () => {
      const stream = new Stream();

      http.get = jest.fn().mockImplementationOnce((_, cb) => {
        cb(stream);
        pemCertChain.split('\n').forEach((chunk) => stream.emit('data', chunk));
        stream.emit('end');
      });

      expect(() =>
        Reflect.construct(JoseHeader, [{ alg: 'RS256', jwk, x5u: 'http://cert-url.com', x5t: 'thumbprint' }]),
      ).toThrowWithMessage(InvalidJoseHeaderException, 'Mismatching certificate sha-1 thumbprint.');
    });

    it('should throw when the provided "x5t" does not match the sha-256 fingerprint of the certificate.', () => {
      expect(() =>
        Reflect.construct(JoseHeader, [{ alg: 'RS256', jwk, x5c, 'x5t#S256': 'thumbprint' }]),
      ).toThrowWithMessage(InvalidJoseHeaderException, 'Mismatching certificate sha-256 thumbprint.');
    });

    it.each(invalidTyps)('should throw when the provided "typ" is invalid.', (typ) => {
      expect(() => Reflect.construct(JoseHeader, [{ alg: 'RS256', typ }])).toThrowWithMessage(
        InvalidJoseHeaderException,
        'Invalid jose header parameter "typ".',
      );
    });

    it.each(invalidCtys)('should throw when the provided "cty" is invalid.', (cty) => {
      expect(() => Reflect.construct(JoseHeader, [{ alg: 'RS256', cty }])).toThrowWithMessage(
        InvalidJoseHeaderException,
        'Invalid jose header parameter "cty".',
      );
    });

    it.each(invalidCrits)('should throw when the provided "crit" is invalid.', (crit) => {
      expect(() => Reflect.construct(JoseHeader, [{ alg: 'RS256', crit }])).toThrow(
        new InvalidJoseHeaderException('Invalid jose header parameter "crit".'),
      );
    });

    it('should throw when the header parameter defined at "crit" is not provided.', () => {
      expect(() => Reflect.construct(JoseHeader, [{ alg: 'RS256', crit: ['kid'] }])).toThrow(
        new InvalidJoseHeaderException('Missing required jose header parameter "kid".'),
      );
    });

    it('should return a valid jose header.', () => {
      let header!: JoseHeader;
      const params: JoseHeaderParams = { alg: 'RS256', jwk: { ...jwk, kid: 'keyid' }, kid: 'keyid', cty: 'JWT' };

      expect(() => (header = Reflect.construct(JoseHeader, [params]))).not.toThrow();

      expect(header).toBeInstanceOf(JoseHeader);
      expect(header).toMatchObject(params);
    });
  });

  describe('isJoseHeader()', () => {
    it.each(invalidDatas)('should return false when the provided data is not a valid jose header.', (data) => {
      expect(JoseHeader.isJoseHeader(data)).toBeFalse();
    });

    it('should return true when the provided data is a valid jose header.', () => {
      expect(JoseHeader.isJoseHeader({ alg: 'RS256' })).toBeTrue();
    });
  });
});
