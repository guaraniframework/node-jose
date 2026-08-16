import { Buffer } from 'buffer';

import { InvalidJsonWebTokenClaimsError } from '../errors/invalid-jsonwebtoken-claims.error';
import { JsonWebTokenClaims } from './jsonwebtoken-claims';
import { JsonWebTokenClaimsParameters } from './jsonwebtoken-claims.parameters';

const invalidClaims: any[] = [
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
];

const invalidIssuers: any[] = [
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

const invalidSubjects: any[] = [
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

const invalidAudiences: any[] = [
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
  '',
  [],
  [undefined],
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
  ['audience', 'audience'],
];

const invalidExpiresAts: any[] = [
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
  1,
];

const invalidNotBefores: any[] = [
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
  Date.now(),
];

const invalidIssuedAts: any[] = [
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
];

const invalidJsonWebTokenIDs: any[] = [
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

const invalidIsJsonWebTokenClaimsParameters: any[] = [
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
  { iss: '' },
];

describe('JSON Web Token Claims', () => {
  describe('constructor', () => {
    it.each(invalidClaims)('should throw when the provided JSON Web Token Claims Parameters is invalid.', (claims) => {
      expect(() => new JsonWebTokenClaims(claims)).toThrowWithMessage(
        TypeError,
        'The provided JSON Web Token Claims Parameters is invalid.',
      );
    });

    it.each(invalidIssuers)('should throw when the provided JSON Web Token Claim "iss" is invalid.', (iss) => {
      expect(() => new JsonWebTokenClaims({ iss })).toThrowWithMessage(
        InvalidJsonWebTokenClaimsError,
        'Invalid JSON Web Token Claim "iss".',
      );
    });

    it.each(invalidSubjects)('should throw when the provided JSON Web Token Claim "sub" is invalid.', (sub) => {
      expect(() => new JsonWebTokenClaims({ sub })).toThrowWithMessage(
        InvalidJsonWebTokenClaimsError,
        'Invalid JSON Web Token Claim "sub".',
      );
    });

    it.each(invalidAudiences)('should throw when the provided JSON Web Token Claim "aud" is invalid.', (aud) => {
      expect(() => new JsonWebTokenClaims({ aud })).toThrowWithMessage(
        InvalidJsonWebTokenClaimsError,
        'Invalid JSON Web Token Claim "aud".',
      );
    });

    it.each(invalidExpiresAts)('should throw when the provided JSON Web Token Claim "exp" is invalid.', (exp) => {
      expect(() => new JsonWebTokenClaims({ exp })).toThrowWithMessage(
        InvalidJsonWebTokenClaimsError,
        'Invalid JSON Web Token Claim "exp".',
      );
    });

    it.each(invalidNotBefores)('should throw when the provided JSON Web Token Claim "nbf" is invalid.', (nbf) => {
      expect(() => new JsonWebTokenClaims({ nbf })).toThrowWithMessage(
        InvalidJsonWebTokenClaimsError,
        'Invalid JSON Web Token Claim "nbf".',
      );
    });

    it.each(invalidIssuedAts)('should throw when the provided JSON Web Token Claim "iat" is invalid.', (iat) => {
      expect(() => new JsonWebTokenClaims({ iat })).toThrowWithMessage(
        InvalidJsonWebTokenClaimsError,
        'Invalid JSON Web Token Claim "iat".',
      );
    });

    it.each(invalidJsonWebTokenIDs)('should throw when the provided JSON Web Token Claim "jti" is invalid.', (jti) => {
      expect(() => new JsonWebTokenClaims({ jti })).toThrowWithMessage(
        InvalidJsonWebTokenClaimsError,
        'Invalid JSON Web Token Claim "jti".',
      );
    });

    it('should return a JSON Web Token Claims with an Issuer.', () => {
      let claims!: JsonWebTokenClaims;

      expect(() => (claims = new JsonWebTokenClaims({ iss: 'https://issuer.example.com' }))).not.toThrow();
      expect(claims.parameters).toStrictEqual({ iss: 'https://issuer.example.com' });
    });

    it('should return a JSON Web Token Claims with a Subject.', () => {
      let claims!: JsonWebTokenClaims;

      expect(() => (claims = new JsonWebTokenClaims({ sub: 'https://subject.example.com' }))).not.toThrow();
      expect(claims.parameters).toStrictEqual({ sub: 'https://subject.example.com' });
    });

    it('should return a JSON Web Token Claims with a single Audience.', () => {
      let claims!: JsonWebTokenClaims;

      expect(() => (claims = new JsonWebTokenClaims({ aud: 'https://audience.example.com' }))).not.toThrow();
      expect(claims.parameters).toStrictEqual({ aud: 'https://audience.example.com' });
    });

    it('should return a JSON Web Token Claims with multiple Audiences.', () => {
      let claims!: JsonWebTokenClaims;

      expect(() => {
        return (claims = new JsonWebTokenClaims({
          aud: ['https://audience.example.com', 'https://audience.example.net'],
        }));
      }).not.toThrow();

      expect(claims.parameters).toStrictEqual({
        aud: ['https://audience.example.com', 'https://audience.example.net'],
      });
    });

    it('should return a JSON Web Token Claims with an Expires At.', () => {
      let claims!: JsonWebTokenClaims;
      const exp = Date.now();

      expect(() => (claims = new JsonWebTokenClaims({ exp }))).not.toThrow();
      expect(claims.parameters).toStrictEqual({ exp });
    });

    it('should return a JSON Web Token Claims with a Not Before.', () => {
      let claims!: JsonWebTokenClaims;
      const nbf = 1;

      expect(() => (claims = new JsonWebTokenClaims({ nbf }))).not.toThrow();
      expect(claims.parameters).toStrictEqual({ nbf });
    });

    it('should return a JSON Web Token Claims with an Issued At.', () => {
      let claims!: JsonWebTokenClaims;
      const iat = Math.floor(Date.now() / 1000);

      expect(() => (claims = new JsonWebTokenClaims({ iat }))).not.toThrow();
      expect(claims.parameters).toStrictEqual({ iat });
    });

    it('should return a JSON Web Token Claims with a JSON Web Token Identifier.', () => {
      let claims!: JsonWebTokenClaims;

      expect(() => (claims = new JsonWebTokenClaims({ jti: '758101ac-ce82-49e4-9d43-1e5bfc622593' }))).not.toThrow();
      expect(claims.parameters).toStrictEqual({ jti: '758101ac-ce82-49e4-9d43-1e5bfc622593' });
    });
  });

  describe('isJsonWebTokenClaimsParameters()', () => {
    it.each(invalidIsJsonWebTokenClaimsParameters)(
      'should return false when the provided JSON Web Token Claims Parameters is invalid.',
      (parameters) => {
        expect(JsonWebTokenClaims.isJsonWebTokenClaimsParameters(parameters)).toBeFalse();
      },
    );

    it('should return true when the provided JSON Web Token Claims Parameters is valid.', () => {
      const now = Math.floor(Date.now() / 1000);

      const parameters: JsonWebTokenClaimsParameters = {
        iss: 'https://issuer.example.com',
        sub: 'https://subject.example.com',
        aud: 'https://audience.example.com',
        exp: now + 3600,
        nbf: now,
        iat: now,
        jti: '758101ac-ce82-49e4-9d43-1e5bfc622593',
      };

      expect(JsonWebTokenClaims.isJsonWebTokenClaimsParameters(parameters)).toBeTrue();
    });
  });

  describe('toString()', () => {
    it('should return the string representation of the JSON Web Token Claims.', () => {
      const claims = new JsonWebTokenClaims({ iat: 1723010455, sub: '078BWDDXasdcg8' });
      expect(claims.toString()).toStrictEqual('{"iat":1723010455,"sub":"078BWDDXasdcg8"}');
    });
  });

  describe('toBuffer()', () => {
    it('should return the string representation of the JSON Web Token Claims.', () => {
      const claims = new JsonWebTokenClaims({ iat: 1723010455, sub: '078BWDDXasdcg8' });
      expect(claims.toBuffer()).toStrictEqual(Buffer.from('{"iat":1723010455,"sub":"078BWDDXasdcg8"}', 'utf8'));
    });
  });
});
