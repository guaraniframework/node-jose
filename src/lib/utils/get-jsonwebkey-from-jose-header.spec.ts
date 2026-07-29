import http from 'http';
import { Stream } from 'stream';

import { jsonStringify } from '@guarani/primitives';

import { InvalidJoseHeaderError } from '../errors/invalid-jose-header.error';
import { JoseHeaderParameters } from '../jose/jose-header.parameters';
import { JsonWebKey } from '../jwk/jsonwebkey';
import { JsonWebKeyParameters } from '../jwk/jsonwebkey.parameters';
import { getJsonWebKeyFromJoseHeader } from './get-jsonwebkey-from-jose-header';

describe('getJsonWebKeyFromJoseHeader()', () => {
  const parameters: JoseHeaderParameters = {
    alg: 'RS256',
    x5c: [
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
    ],
  };

  const jwk: JsonWebKeyParameters = {
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
    kid: 'rsa-key',
    x5c: parameters.x5c!,
  };

  it('should return null when none of the JOSE Header Parameters "jku" or "jwk" are present.', async () => {
    await expect(getJsonWebKeyFromJoseHeader(parameters)).resolves.toBeNull();
  });

  it('should throw when failing to retrieve a JSON Web Key from the JSON Web Key Set at the provided JOSE Header Parameter "jku".', async () => {
    http.get = jest.fn().mockImplementation((_, callback) => {
      const stream = new Stream();
      callback(stream);
      stream.emit('data', jsonStringify({ keys: [jwk] }));
      stream.emit('end');
    });

    await expect(
      getJsonWebKeyFromJoseHeader({ ...parameters, jku: 'http://jku-url.com', kid: 'key-id' }),
    ).rejects.toThrowWithMessage(InvalidJoseHeaderError, 'Invalid JOSE Header Parameter "jku".');
  });

  it('should throw when the provided JOSE Header Parameter "kid" does not match the provided JSON Web Key Parameter "jwk.kid".', async () => {
    await expect(getJsonWebKeyFromJoseHeader({ ...parameters, jwk, kid: 'key-id' })).rejects.toThrowWithMessage(
      InvalidJoseHeaderError,
      'Mismatching JOSE Header and JSON Web Key Parameters "kid".',
    );
  });

  it('should throw when the provided JOSE Header Parameter "jwk" is invalid.', async () => {
    await expect(
      getJsonWebKeyFromJoseHeader({ ...parameters, jwk: { ...jwk, kty: 'oct' } }),
    ).rejects.toThrowWithMessage(InvalidJoseHeaderError, 'Invalid JOSE Header Parameter "jwk".');
  });

  it('should throw when the provided JOSE Header Parameter "alg" does not match the provided JSON Web Key Parameter "alg".', async () => {
    await expect(getJsonWebKeyFromJoseHeader({ ...parameters, jwk, alg: 'HS256' })).rejects.toThrowWithMessage(
      InvalidJoseHeaderError,
      'Mismatching JOSE Header and JSON Web Key Parameters "alg".',
    );
  });

  it('should return a JSON Web Key from the provided JOSE Header Parameter "jku".', async () => {
    let jsonWebKey!: JsonWebKey | null;

    http.get = jest.fn().mockImplementationOnce((_, callback) => {
      const stream = new Stream();
      callback(stream);
      stream.emit('data', jsonStringify({ keys: [jwk] }));
      stream.emit('end');
    });

    await expect(async () => {
      jsonWebKey = await getJsonWebKeyFromJoseHeader({ alg: 'RS256', jku: 'http://jku-url.com', kid: 'rsa-key' });
    }).resolves.not.toThrow();

    expect(jsonWebKey).toBeInstanceOf(JsonWebKey);
    expect(jsonWebKey!.parameters).toStrictEqual(jwk);
  });

  it('should return a JSON Web Key from the provided JOSE Header Parameter "jwk".', async () => {
    let jsonWebKey!: JsonWebKey | null;

    await expect(async () => {
      jsonWebKey = await getJsonWebKeyFromJoseHeader({ alg: 'RS256', jwk });
    }).resolves.not.toThrow();

    expect(jsonWebKey).toBeInstanceOf(JsonWebKey);
    expect(jsonWebKey!.parameters).toStrictEqual(jwk);
  });
});
