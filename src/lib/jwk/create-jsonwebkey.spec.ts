import { Buffer } from 'buffer';
import { X509Certificate } from 'crypto';

import { InvalidJsonWebKeyError } from '../errors/invalid-jsonwebkey.error';
import { createJsonWebKey } from './create-jsonwebkey';
import { JsonWebKey } from './jsonwebkey';
import { JsonWebKeyParameters } from './jsonwebkey.parameters';

const invalidParameters: any[] = [
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
  () => {},
  [],
];

const invalidKtys: any[] = [
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
  'a',
];

describe('createJsonWebKey()', () => {
  const ellipticCurveParameters: JsonWebKeyParameters = {
    kty: 'EC',
    crv: 'P-256',
    x: '4c_cS6IT6jaVQeobt_6BDCTmzBaBOTmmiSCpjd5a6Og',
    y: 'mnrPnCFTDkGdEwilabaqM7DzwlAFgetZTmP9ycHPxF8',
  };

  const octetKeyPairParameters: JsonWebKeyParameters = {
    kty: 'OKP',
    crv: 'Ed25519',
    x: 'aNoALKSUE1UsotuZvHUj1HEGqhpzLtsSTLmkBITDMAk',
  };

  const rsaParameters: JsonWebKeyParameters = {
    kty: 'RSA',
    n:
      'xjpFydzTbByzL5jhEa2yQO63dpS9d9SKaN107AR69skKiTR4uK1c4SzDt4YcurDB' +
      'yhgKNzeBo6Vq3IRrkrltp97LKWfeZdM-leGt8-UTZEWqrNf3UGOEj8kI6lbjiG-S' +
      'n_yNHcVA9qBV22norZkgXctHLeFbY6TmpD-I8_UiplZUHoc9KlYc7crCQRa-O7tK' +
      'FDULNTMjjifc0dmuYP7ZcYAZXmRmoOpQuDr8s7OZY7TAqN0btMfA7RpUCWLT6TMR' +
      'QPX8GcyTxfbkOrSTFueKMHVNdXDtl068XXJ9mkjORiEmwlzqSBoxdeLWcNf_u20S' +
      '5JG5iK0nsm1uZYu-02XN-w',
    e: 'AQAB',
  };

  const octetSequenceParameters: JsonWebKeyParameters = {
    kty: 'oct',
    k: 'qDM80igvja4Tg_tNsEuWDhl2bMM6_NgJEldFhIEuwqQ',
  };

  const parameters: JsonWebKeyParameters = {
    kty: 'RSA',
    n:
      'oxz99bTZPitqTDFHPLKm4T5y_rS7rJ4BE5GLNT41eRVaFSnCemfCvJJDgxjr2v7x' +
      'URJjXrzKT8UGhWz9EFMXEtM9-ty_dTnEVj3hSR79Jl2xAVedjIcJgWJBKhQomL4y' +
      'KGn2YOE2bgQmH1HzsQNf9KcPTIzYuMwoCvYKJLfHRzg4WNqajJqyLyOwNcTRkCCo' +
      'ShNUdJouYdyzkRZqkvjgAWivpH0RzWyoviREbwxCi_se7J1ajVnhMvl-iKJwUlG8' +
      'hGwm5UM6a4ZSKX4NbLfDJX7FNyii1mjfJrhl3prt4Pkae_JYG_8jy6h-QH5-QUzC' +
      'wf-zUq81MDbyQMj_A1_DBw',
    e: 'AQAB',
    d:
      'NR9cFomvtu-szuO9r6b_cpxEF3AFL1LGRvk_vTdlcunhTMMs83CXm5KHKksThV9C' +
      'eITkmBYkTZZ9aTb1tDtbaGYj6W-7axJFP1En7giJqdUZsLY4OWxBTEITtwCZuCU5' +
      'cLAR7btrXqk7QTgPhbbzqVo_QU8dxhG3eNpos0ynOiovHKoM7wxdfP1Q0Wb8gDtK' +
      'T4q7rZw8VGT52war3vI-Bv1gTTuTdDsZQcSMG-1ioTb7xZJxf_Ia7eDpvJ-UhtIo' +
      'qrXM6qrdeP6t1mMSghp_ijflfBKR_kKcpO38K_7GLtZUeV-pZddLLlNlDuAbri71' +
      'jhc34oWYCty9TGnCu7UOAQ',
    p:
      '5o9x5PXeSm3DlV9uVeiSXM4zkyjQKqLdjPXfBGaSXujcbhcn7FSqKPbzaXKpyOmG' +
      'k8i9HXTaFgQZRDqwp3be7iyKGJBJIBMu791N9FnXarZsOtgCu4OvSDPSZNiVA_Xy' +
      '7YCa9QcfRsIxfnkmQyY8LqO0uvUZqLpj9BW_rSH1eFk',
    q:
      'tRxkwZHTqs9BPA1SGClhpYyCWuk_Vzd_K_rHPpLmWULSZ84-4JSaa9uPGxN9vik_' +
      'nThuWs_qjcYlae0c8v_Ufcf5L1V1l2uT8ZbT4JeEmHkndiyUp8r-Wjd4_UH1MSSj' +
      'HQ6sjydJ-V8SNXwOacJHCNTVEcWgXElv31qLP8alql8',
    dp:
      'zK6J-S7BMigx2vkGlePLk_JHXRx9eWxu7UYVv-1jgjiOAHo0Kh2blpRt0a5GxqNy' +
      'ot4x7eWf-q2W1LiZvYHNNXp6-oWVNZFyOOWp4ASmNglPGgpMmrW0NZAz9u1DlWmS' +
      'SYDDkEXLYWDi2Zmp-zEFeo5A0zzmk6EtPTLVoFkmd7k',
    dq:
      'y78lmp5zgbWnredOc-AZ-iQYgi3lFDla2B9IBx08By8lhaKBGiYTk0Ntuwgybbv5' +
      '1OWnQIKnXNeNP52A897bLqXJr3Z00-Qyi5cixYevo9iojEma8ylq_BNsCX4qWR7e' +
      'YdIgTuvkTKan1YO6sz_cqhLFoTizLx9uu9cg0J6pwQ',
    qi:
      'J_ug_1Ql0d3KiCm-2KOcH_OhXJ-2fvNHde2E5GUXg4tyEEfBYXSDpij3lbQEzZ_J' +
      'yUFMt5AtTto8yz_NReVRdQb7m72qI3nM9Tpgu1vOIF-2EQyhQYSqm9wREz63p2ZE' +
      '1lMW0RqvTUadDuuKFyla2jH73EqwV5G7u1RdFBeBcsw',
    x5c: [
      'MIIDnTCCAoWgAwIBAgIUUSmfezMSrdGPCWNDc2GIqCdNk4IwDQYJKoZIhvcNAQEL' +
        'BQAwRTELMAkGA1UEBhMCQlIxFDASBgNVBAoMC0V4YW1wbGUgUEtJMSAwHgYDVQQD' +
        'DBdFeGFtcGxlIEludGVybWVkaWF0ZSBDQTAeFw0yNjA2MjUwNDQ0NThaFw0yODA5' +
        'MjcwNDQ5NThaMDoxCzAJBgNVBAYTAkJSMRQwEgYDVQQKDAtFeGFtcGxlIFBLSTEV' +
        'MBMGA1UEAwwMZXhhbXBsZS50ZXN0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB' +
        'CgKCAQEAoxz99bTZPitqTDFHPLKm4T5y/rS7rJ4BE5GLNT41eRVaFSnCemfCvJJD' +
        'gxjr2v7xURJjXrzKT8UGhWz9EFMXEtM9+ty/dTnEVj3hSR79Jl2xAVedjIcJgWJB' +
        'KhQomL4yKGn2YOE2bgQmH1HzsQNf9KcPTIzYuMwoCvYKJLfHRzg4WNqajJqyLyOw' +
        'NcTRkCCoShNUdJouYdyzkRZqkvjgAWivpH0RzWyoviREbwxCi/se7J1ajVnhMvl+' +
        'iKJwUlG8hGwm5UM6a4ZSKX4NbLfDJX7FNyii1mjfJrhl3prt4Pkae/JYG/8jy6h+' +
        'QH5+QUzCwf+zUq81MDbyQMj/A1/DBwIDAQABo4GPMIGMMAwGA1UdEwEB/wQCMAAw' +
        'HQYDVR0OBBYEFLXBH6cZivQYIND/RDGbFImzbIE/MB8GA1UdIwQYMBaAFBK7O69e' +
        'rMjp7Qd6t5vSlDhbnGppMA4GA1UdDwEB/wQEAwIFoDATBgNVHSUEDDAKBggrBgEF' +
        'BQcDATAXBgNVHREEEDAOggxleGFtcGxlLnRlc3QwDQYJKoZIhvcNAQELBQADggEB' +
        'AHup8jKtq/L9bW066QUy1tRdn02NdsBzeTOC4FHiyHgRCyBECRvWx2JdgRtwOQVC' +
        'dT97VnZlZODpefBGaMCGFIBfFtJaNymSx/Kcp1Vuf1uVMpCv6UKbYj0Tqk8pGxME' +
        'DLd7Ix6EuL/X0+qovla1GoNKLYitQ+kgzIHVflU9Oi55GZmS5hefc3M1fGfY4GBb' +
        'A3keorRQdK9UyRtTU8C+8DWsgknUHwjbOY6DWjflsQxlqq34IZYfWQPhoG8iRP4Z' +
        'WiP4rrJ/ubHe6LSPlz/BctNp8GMPQ/zbAAUHe8+Sg51EKVD+cyhd3oz4ogb5cf5t' +
        'gqA9v7CQd2Ih92LHkvaOcQM=',
      'MIIDdjCCAl6gAwIBAgIULKpn8f5ChJJsH2CeN9yvrARNHBgwDQYJKoZIhvcNAQEL' +
        'BQAwPTELMAkGA1UEBhMCQlIxFDASBgNVBAoMC0V4YW1wbGUgUEtJMRgwFgYDVQQD' +
        'DA9FeGFtcGxlIFJvb3QgQ0EwHhcNMjYwNjI1MDQ0NDU4WhcNMzYwNjIyMDQ0OTU4' +
        'WjBFMQswCQYDVQQGEwJCUjEUMBIGA1UECgwLRXhhbXBsZSBQS0kxIDAeBgNVBAMM' +
        'F0V4YW1wbGUgSW50ZXJtZWRpYXRlIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A' +
        'MIIBCgKCAQEArLwkUn9VHXNSyFsAzZnw9uJXiO7f1Gv9K4Eas/pFxsPp0R4ms6xG' +
        'yNos1Y56bCTjfOI8Vfrytja2PJQ8T0T/P8Y8vDg6GL9aAK+4Bldhk+/WgtqvI7N6' +
        'DFoaAyUbNFFyJVxpLDeUNBMgTz9j7gXB1vbAYgPB1iVuxxR7Fb7bvbTWZoKsSHnB' +
        '5bKgEchkVzahgUJrmJBtaF+fWpD8UivEUKSV8TcQEui793G5w8YctQTaeh69cSom' +
        'zi9vI/pu0Sj58twr3x9eAuagOzp4SEBSYpjMAAI0vjzmZQRu8cR21i0lE6KQs1H1' +
        '/gOkrehW45F61ktocFhVCrH0F9vHvEQ/DQIDAQABo2YwZDASBgNVHRMBAf8ECDAG' +
        'AQH/AgEAMB0GA1UdDgQWBBQSuzuvXqzI6e0Hereb0pQ4W5xqaTAfBgNVHSMEGDAW' +
        'gBTAPoa/Wu9rIKJ/I7ulrYuV9zo+JDAOBgNVHQ8BAf8EBAMCAYYwDQYJKoZIhvcN' +
        'AQELBQADggEBABIhB6jSrA5Owwg9bOao1QQ3r6VSlfRDDh0uyfilYUPwbzQGh7Oi' +
        'zHoZqRpa0Wq5r2zbHfPpNdzD6HxzQsjiBZ24EerSKW2ku64KJrYmlH9hVjhdoGEr' +
        'syAcb93YEhAXcTZXEQGOkaSlcYcAA4QEVIAXJNTFPaI+AThGrxqPoavWTrT9TIiR' +
        'iBGHG9qkSR8MHy/bbxFkBwm1R38nTKsu5g8xipP6oBcW69vmYhcGY1iCLbq0Fge/' +
        'e1bA3ocVLAJGfBgcP7rNqke46YUyrQRpOQurLoHKbwBvHXTGMoBaeueQcfTbBP4/' +
        'VFMEtap3ulAWrzN1ZVPTM0BrWVgUZ3uKZew=',
      'MIIDbjCCAlagAwIBAgIUGrj/wLSBNczEQGDq0996l1nwR1kwDQYJKoZIhvcNAQEL' +
        'BQAwPTELMAkGA1UEBhMCQlIxFDASBgNVBAoMC0V4YW1wbGUgUEtJMRgwFgYDVQQD' +
        'DA9FeGFtcGxlIFJvb3QgQ0EwHhcNMjYwNjI1MDQ0NDU4WhcNMzYwNjIyMDQ0OTU4' +
        'WjA9MQswCQYDVQQGEwJCUjEUMBIGA1UECgwLRXhhbXBsZSBQS0kxGDAWBgNVBAMM' +
        'D0V4YW1wbGUgUm9vdCBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB' +
        'AMivoZh0onnabGULag2JmMINAEOGUz2QBbMwL1ZNnfXrIZVf6lTpOZBqMbHuEbPY' +
        'BCYow8aBvLGQZj2haEMmPIvmH3ly9i6tH9rg+CTQoIY5G9n4s5badqtffwepxKZ0' +
        'VudTdhuCyBfpChURjLOQXc3OOqNb+bbyyq3uHUIxndvK2BSAhVuSLEvtSsgcTA2W' +
        'Jr4Czy5iNDTkgzpZlLOpJLwhcQy1tQl+uap4/2LWDOfmxp/PYsdXszFCiW3qtUuo' +
        'nDrf67M5kexu29cS7ok5xqCSuT/Bs8ZWJJLNqHra8Zs+1AMnNYbg97ZlilT2uRha' +
        '6srmXXyyPDqXVOzNY5XZi0kCAwEAAaNmMGQwEgYDVR0TAQH/BAgwBgEB/wIBATAd' +
        'BgNVHQ4EFgQUwD6Gv1rvayCifyO7pa2Llfc6PiQwHwYDVR0jBBgwFoAUwD6Gv1rv' +
        'ayCifyO7pa2Llfc6PiQwDgYDVR0PAQH/BAQDAgGGMA0GCSqGSIb3DQEBCwUAA4IB' +
        'AQAgUfPTVlsufv6N9bAVKmFi7rGiwOuhj+5iLb28G4PuNdiTyjf2gAf8H8I0MutS' +
        '89BTsDqDcAOh8tWuzOaNn0tJPvf02AhBD4paX9Yi0cZE2QeVwh3DZf0EFyK4OY0l' +
        'VaIAJt3ZvaanBYqEqct+3S8NGhrTwWopjulNRPCnZQ863BC1zZnKPHKAo/mE0AYU' +
        'xMWbd5bmSmqvZMuVlN22d2QfOALmL8dAwC+L512JT0G52nuIm3Bc3IYjkf3D6Wgs' +
        'lcsOhYIRf4lgJ6MN4iLLMcZQicQGEJMu1lfDkfXQdEYgQFBiX1cBPl8C3/Smuv2y' +
        'k0ZiAXncRDT5pElDu8TCqHS3',
    ],
  };

  it.each(invalidParameters)(
    'should throw when the provided JSON Web Key Parameters is invalid.',
    async (parameters) => {
      await expect(createJsonWebKey(parameters)).rejects.toThrowWithMessage(
        TypeError,
        'The provided JSON Web Key Parameters is invalid.',
      );
    },
  );

  it.each(invalidKtys)('should throw when the provided JSON Web Key Parameter "kty" is invalid.', async (kty) => {
    await expect(createJsonWebKey({ ...parameters, kty })).rejects.toThrowWithMessage(
      InvalidJsonWebKeyError,
      'Invalid JSON Web Key Parameter "kty".',
    );
  });

  it('should return an Elliptic Curve JSON Web Key.', async () => {
    let jwk!: JsonWebKey;

    await expect(async () => (jwk = await createJsonWebKey(ellipticCurveParameters))).resolves.not.toThrow();

    expect(jwk.parameters).toStrictEqual(ellipticCurveParameters);
    expect(ellipticCurveParameters).toMatchObject(jwk.cryptoKey.export({ format: 'jwk' }));
    expect(jwk.certificateChain).toBeNull();
  });

  it('should return an Octet Key Pair JSON Web Key.', async () => {
    let jwk!: JsonWebKey;

    await expect(async () => (jwk = await createJsonWebKey(octetKeyPairParameters))).resolves.not.toThrow();

    expect(jwk.parameters).toStrictEqual(octetKeyPairParameters);
    expect(octetKeyPairParameters).toMatchObject(jwk.cryptoKey.export({ format: 'jwk' }));
    expect(jwk.certificateChain).toBeNull();
  });

  it('should return an RSA JSON Web Key.', async () => {
    let jwk!: JsonWebKey;

    await expect(async () => (jwk = await createJsonWebKey(rsaParameters))).resolves.not.toThrow();

    expect(jwk.parameters).toStrictEqual(rsaParameters);
    expect(rsaParameters).toMatchObject(jwk.cryptoKey.export({ format: 'jwk' }));
    expect(jwk.certificateChain).toBeNull();
  });

  it('should return an Octet Sequence JSON Web Key.', async () => {
    let jwk!: JsonWebKey;

    await expect(async () => (jwk = await createJsonWebKey(octetSequenceParameters))).resolves.not.toThrow();

    expect(jwk.parameters).toStrictEqual(octetSequenceParameters);
    expect(octetSequenceParameters).toMatchObject(jwk.cryptoKey.export({ format: 'jwk' }));
    expect(jwk.certificateChain).toBeNull();
  });

  it('should return a JSON Web Key.', async () => {
    let jwk!: JsonWebKey;

    await expect(async () => (jwk = await createJsonWebKey(parameters))).resolves.not.toThrow();

    expect(jwk.parameters).toStrictEqual(parameters);

    expect(parameters).toMatchObject(jwk.cryptoKey.export({ format: 'jwk' }));

    expect(jwk.certificateChain).toBeArrayOfSize(3);
    expect(jwk.certificateChain).toSatisfyAll((certificate) => certificate instanceof X509Certificate);

    const { certificateChain, cryptoKey } = jwk;

    jwk.cryptoKey = null!;
    jwk.certificateChain = null;

    expect(jwk.cryptoKey).toBe(cryptoKey);
    expect(jwk.certificateChain).toBe(certificateChain);
  });
});
