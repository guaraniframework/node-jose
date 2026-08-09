import { Buffer } from 'buffer';
import crypto from 'crypto';
import https from 'https';
import { Stream } from 'stream';

import { jsonStringify } from '@guarani/primitives';

import { InvalidJoseHeaderError } from '../../../errors/invalid-jose-header.error';
import { KeyManagementAlgorithm } from '../../../jwa/jwe/alg/key-management-algorithm.type';
import { AESCBCJsonWebEncryptionContentEncryptionBackend } from '../../../jwa/jwe/enc/aescbc/aescbc-jsonwebencryption-content-encryption.backend';
import { OctetSequenceJsonWebKey } from '../../../jwa/jwk/oct/octet-sequence.jsonwebkey';
import { JsonWebEncryptionHeaderParameters } from '../../jsonwebencryption-header.parameters';
import { GeneralJsonWebEncryptionToken } from './general-jsonwebencryption.token';
import { serialize } from './serialize';

jest.mock<typeof crypto>('crypto', () => ({
  ...jest.requireActual('crypto'),
  randomBytes: jest
    .fn()
    .mockImplementation((_, cb) => cb(null, Buffer.from('BNMfxVSd_P4LZJ36P6pqzmt81C1vawnbyLEA8I-cLM8', 'base64url'))),
}));

const invalidPlaintexts: any[] = [
  undefined,
  null,
  true,
  1,
  1.2,
  1n,
  'a',
  Symbol('a'),
  Buffer,
  () => 1,
  {},
  [],
  Buffer.alloc(0),
];

const invalidProtectedHeaders: any[] = [
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

const invalidUnprotectedHeaders: any[] = [
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

const invalidRecipients: any[] = [
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

const invalidRecipientUnprotectedHeaders: any[] = [
  [[{ recipientUnprotectedHeader: undefined }]],
  [[{ recipientUnprotectedHeader: null }]],
  [[{ recipientUnprotectedHeader: true }]],
  [[{ recipientUnprotectedHeader: 1 }]],
  [[{ recipientUnprotectedHeader: 1.2 }]],
  [[{ recipientUnprotectedHeader: 1n }]],
  [[{ recipientUnprotectedHeader: 'a' }]],
  [[{ recipientUnprotectedHeader: Symbol('a') }]],
  [[{ recipientUnprotectedHeader: Buffer }]],
  [[{ recipientUnprotectedHeader: Buffer.alloc(1) }]],
  [[{ recipientUnprotectedHeader: () => 1 }]],
  [[{ recipientUnprotectedHeader: [] }]],
];

const repeatedJoseHeaderParameters: Partial<JsonWebEncryptionHeaderParameters>[][] = [
  [{ alg: 'A128KW' }, { alg: 'A128KW' }, { enc: 'A128CBC-HS256' }],
  [{ alg: 'A128KW' }, { enc: 'A128CBC-HS256' }, { alg: 'A128KW' }],
  [{ enc: 'A128CBC-HS256' }, { alg: 'A128KW' }, { alg: 'A128KW' }],
  [{ alg: 'A128KW' }, { alg: 'A128KW' }, { alg: 'A128KW' }],
];

const forbiddenKeyManagementAlgorithms: KeyManagementAlgorithm[] = ['ECDH-ES', 'dir'];

const invalidSerializeOptions: any[] = [null, true, 1, 1.2, 1n, 'a', Symbol('a'), Buffer, Buffer.alloc(1), () => 1, []];
const invalidAads: any[] = [null, true, 1, 1.2, 1n, 'a', Symbol('a'), Buffer, () => 1, {}, [], Buffer.alloc(0)];

const invalidJwks: any[] = [
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
  [undefined],
  [null],
  [true],
  [1],
  [1.2],
  [1n],
  ['a'],
  [Symbol('a')],
  [Buffer],
  [Buffer.alloc(1)],
  [() => 1],
  [{}],
  [[]],
  [
    new OctetSequenceJsonWebKey({ kty: 'oct', k: '0123456789abcdef' }),
    new OctetSequenceJsonWebKey({ kty: 'oct', k: '0123456789abcdef' }),
  ],
];

const invalidDetacheds: any[] = [null, 1, 1.2, 1n, 'a', Symbol('a'), Buffer, Buffer.alloc(1), () => 1, {}, []];

describe('serialize()', () => {
  // #region Uncompressed Attached Token without Additional Authenticated Data
  const uncompressedProtectedAttachedTokenNoAad: GeneralJsonWebEncryptionToken = {
    protected:
      'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyJ9',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    aad: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyJ9',
    ciphertext: 'KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY',
    tag: 'pf7CC-iGb8R2ZstoWHErWw',
    recipients: [{ encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ' }],
  };

  const uncompressedUnprotectedAttachedTokenNoAad: GeneralJsonWebEncryptionToken = {
    unprotected: { alg: 'A128KW', enc: 'A128CBC-HS256', jku: 'https://server.example.com/keys.jwks', kid: '7' },
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    ciphertext: 'KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY',
    tag: 'wOere2l7R7PoakOvvvxFCg',
    recipients: [{ encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ' }],
  };

  const uncompressedRecipientAttachedTokenNoAad: GeneralJsonWebEncryptionToken = {
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    ciphertext: 'KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY',
    tag: 'wOere2l7R7PoakOvvvxFCg',
    recipients: [
      {
        header: { alg: 'A128KW', enc: 'A128CBC-HS256', jku: 'https://server.example.com/keys.jwks', kid: '7' },
        encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
      },
    ],
  };

  const uncompressedProtectedAndUnprotectedAttachedTokenNoAad: GeneralJsonWebEncryptionToken = {
    protected: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    unprotected: { alg: 'A128KW', jku: 'https://server.example.com/keys.jwks', kid: '7' },
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    aad: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    ciphertext: 'KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY',
    tag: 'Mz-VPPyU4RlcuYv1IwIvzw',
    recipients: [{ encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ' }],
  };

  const uncompressedProtectedAndRecipientAttachedTokenNoAad: GeneralJsonWebEncryptionToken = {
    protected: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    aad: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    ciphertext: 'KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY',
    tag: 'Mz-VPPyU4RlcuYv1IwIvzw',
    recipients: [
      {
        header: { alg: 'A128KW', jku: 'https://server.example.com/keys.jwks', kid: '7' },
        encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
      },
    ],
  };

  const uncompressedUnprotectedAndRecipientAttachedTokenNoAad: GeneralJsonWebEncryptionToken = {
    unprotected: { enc: 'A128CBC-HS256' },
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    ciphertext: 'KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY',
    tag: 'wOere2l7R7PoakOvvvxFCg',
    recipients: [
      {
        header: { alg: 'A128KW', jku: 'https://server.example.com/keys.jwks', kid: '7' },
        encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
      },
    ],
  };

  const uncompressedFullAttachedTokenNoAad: GeneralJsonWebEncryptionToken = {
    protected: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    unprotected: { jku: 'https://server.example.com/keys.jwks' },
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    aad: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    ciphertext: 'KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY',
    tag: 'Mz-VPPyU4RlcuYv1IwIvzw',
    recipients: [
      { header: { alg: 'A128KW', kid: '7' }, encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ' },
    ],
  };
  // #endregion
  // #region Uncompressed Detached Token without Additional Authenticated Data
  const uncompressedProtectedDetachedTokenNoAad: GeneralJsonWebEncryptionToken = {
    protected:
      'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyJ9',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    aad: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyJ9',
    tag: 'pf7CC-iGb8R2ZstoWHErWw',
    recipients: [{ encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ' }],
  };

  const uncompressedUnprotectedDetachedTokenNoAad: GeneralJsonWebEncryptionToken = {
    unprotected: { alg: 'A128KW', enc: 'A128CBC-HS256', jku: 'https://server.example.com/keys.jwks', kid: '7' },
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    tag: 'wOere2l7R7PoakOvvvxFCg',
    recipients: [{ encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ' }],
  };

  const uncompressedRecipientDetachedTokenNoAad: GeneralJsonWebEncryptionToken = {
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    tag: 'wOere2l7R7PoakOvvvxFCg',
    recipients: [
      {
        header: { alg: 'A128KW', enc: 'A128CBC-HS256', jku: 'https://server.example.com/keys.jwks', kid: '7' },
        encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
      },
    ],
  };

  const uncompressedProtectedAndUnprotectedDetachedTokenNoAad: GeneralJsonWebEncryptionToken = {
    protected: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    unprotected: { alg: 'A128KW', jku: 'https://server.example.com/keys.jwks', kid: '7' },
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    aad: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    tag: 'Mz-VPPyU4RlcuYv1IwIvzw',
    recipients: [{ encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ' }],
  };

  const uncompressedProtectedAndRecipientDetachedTokenNoAad: GeneralJsonWebEncryptionToken = {
    protected: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    aad: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    tag: 'Mz-VPPyU4RlcuYv1IwIvzw',
    recipients: [
      {
        header: { alg: 'A128KW', jku: 'https://server.example.com/keys.jwks', kid: '7' },
        encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
      },
    ],
  };

  const uncompressedUnprotectedAndRecipientDetachedTokenNoAad: GeneralJsonWebEncryptionToken = {
    unprotected: { enc: 'A128CBC-HS256' },
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    tag: 'wOere2l7R7PoakOvvvxFCg',
    recipients: [
      {
        header: { alg: 'A128KW', jku: 'https://server.example.com/keys.jwks', kid: '7' },
        encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
      },
    ],
  };

  const uncompressedFullDetachedTokenNoAad: GeneralJsonWebEncryptionToken = {
    protected: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    unprotected: { jku: 'https://server.example.com/keys.jwks' },
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    aad: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    tag: 'Mz-VPPyU4RlcuYv1IwIvzw',
    recipients: [
      { header: { alg: 'A128KW', kid: '7' }, encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ' },
    ],
  };
  // #endregion
  // #region Compressed Attached Token without Additional Authenticated Data
  const compressedProtectedAttachedTokenNoAad: GeneralJsonWebEncryptionToken = {
    protected:
      'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiemlwIjoiREVGIiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyJ9',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    aad: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiemlwIjoiREVGIiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyJ9',
    ciphertext: '7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA',
    tag: '8nmSbluZF1Ws1sABt49r6Q',
    recipients: [{ encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ' }],
  };

  const compressedUnprotectedAttachedTokenNoAad: GeneralJsonWebEncryptionToken = {
    unprotected: {
      alg: 'A128KW',
      enc: 'A128CBC-HS256',
      zip: 'DEF',
      jku: 'https://server.example.com/keys.jwks',
      kid: '7',
    },
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    ciphertext: '7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA',
    tag: '6mQsBNyxIUzsP37fC54ZjQ',
    recipients: [{ encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ' }],
  };

  const compressedRecipientAttachedTokenNoAad: GeneralJsonWebEncryptionToken = {
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    ciphertext: '7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA',
    tag: '6mQsBNyxIUzsP37fC54ZjQ',
    recipients: [
      {
        header: {
          alg: 'A128KW',
          enc: 'A128CBC-HS256',
          zip: 'DEF',
          jku: 'https://server.example.com/keys.jwks',
          kid: '7',
        },
        encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
      },
    ],
  };

  const compressedProtectedAndUnprotectedAttachedTokenNoAad: GeneralJsonWebEncryptionToken = {
    protected: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    unprotected: { alg: 'A128KW', zip: 'DEF', jku: 'https://server.example.com/keys.jwks', kid: '7' },
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    aad: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    ciphertext: '7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA',
    tag: 'FVFsNAUL3jgdAmZnSVxAFQ',
    recipients: [{ encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ' }],
  };

  const compressedProtectedAndRecipientAttachedTokenNoAad: GeneralJsonWebEncryptionToken = {
    protected: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    aad: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    ciphertext: '7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA',
    tag: 'FVFsNAUL3jgdAmZnSVxAFQ',
    recipients: [
      {
        header: { alg: 'A128KW', zip: 'DEF', jku: 'https://server.example.com/keys.jwks', kid: '7' },
        encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
      },
    ],
  };

  const compressedUnprotectedAndRecipientAttachedTokenNoAad: GeneralJsonWebEncryptionToken = {
    unprotected: { enc: 'A128CBC-HS256' },
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    ciphertext: '7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA',
    tag: '6mQsBNyxIUzsP37fC54ZjQ',
    recipients: [
      {
        header: { alg: 'A128KW', zip: 'DEF', jku: 'https://server.example.com/keys.jwks', kid: '7' },
        encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
      },
    ],
  };

  const compressedFullAttachedTokenNoAad: GeneralJsonWebEncryptionToken = {
    protected: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    unprotected: { jku: 'https://server.example.com/keys.jwks' },
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    aad: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    ciphertext: '7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA',
    tag: 'FVFsNAUL3jgdAmZnSVxAFQ',
    recipients: [
      {
        header: { alg: 'A128KW', zip: 'DEF', kid: '7' },
        encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
      },
    ],
  };
  // #endregion
  // #region Compressed Detached Token without Additional Authenticated Data
  const compressedProtectedDetachedTokenNoAad: GeneralJsonWebEncryptionToken = {
    protected:
      'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiemlwIjoiREVGIiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyJ9',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    aad: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiemlwIjoiREVGIiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyJ9',
    tag: '8nmSbluZF1Ws1sABt49r6Q',
    recipients: [{ encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ' }],
  };

  const compressedUnprotectedDetachedTokenNoAad: GeneralJsonWebEncryptionToken = {
    unprotected: {
      alg: 'A128KW',
      enc: 'A128CBC-HS256',
      zip: 'DEF',
      jku: 'https://server.example.com/keys.jwks',
      kid: '7',
    },
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    tag: '6mQsBNyxIUzsP37fC54ZjQ',
    recipients: [{ encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ' }],
  };

  const compressedRecipientDetachedTokenNoAad: GeneralJsonWebEncryptionToken = {
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    tag: '6mQsBNyxIUzsP37fC54ZjQ',
    recipients: [
      {
        header: {
          alg: 'A128KW',
          enc: 'A128CBC-HS256',
          zip: 'DEF',
          jku: 'https://server.example.com/keys.jwks',
          kid: '7',
        },
        encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
      },
    ],
  };

  const compressedProtectedAndUnprotectedDetachedTokenNoAad: GeneralJsonWebEncryptionToken = {
    protected: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    unprotected: { alg: 'A128KW', zip: 'DEF', jku: 'https://server.example.com/keys.jwks', kid: '7' },
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    aad: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    tag: 'FVFsNAUL3jgdAmZnSVxAFQ',
    recipients: [{ encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ' }],
  };

  const compressedProtectedAndRecipientDetachedTokenNoAad: GeneralJsonWebEncryptionToken = {
    protected: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    aad: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    tag: 'FVFsNAUL3jgdAmZnSVxAFQ',
    recipients: [
      {
        header: { alg: 'A128KW', zip: 'DEF', jku: 'https://server.example.com/keys.jwks', kid: '7' },
        encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
      },
    ],
  };

  const compressedUnprotectedAndRecipientDetachedTokenNoAad: GeneralJsonWebEncryptionToken = {
    unprotected: { enc: 'A128CBC-HS256' },
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    tag: '6mQsBNyxIUzsP37fC54ZjQ',
    recipients: [
      {
        header: { alg: 'A128KW', zip: 'DEF', jku: 'https://server.example.com/keys.jwks', kid: '7' },
        encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
      },
    ],
  };

  const compressedFullDetachedTokenNoAad: GeneralJsonWebEncryptionToken = {
    protected: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    unprotected: { jku: 'https://server.example.com/keys.jwks' },
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    aad: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    tag: 'FVFsNAUL3jgdAmZnSVxAFQ',
    recipients: [
      {
        header: { alg: 'A128KW', zip: 'DEF', kid: '7' },
        encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
      },
    ],
  };
  // #endregion
  // #region Uncompressed Attached Token with Additional Authenticated Data
  const uncompressedProtectedAttachedToken: GeneralJsonWebEncryptionToken = {
    protected:
      'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyJ9',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    aad:
      'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyJ9.' +
      'YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE',
    ciphertext: 'KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY',
    tag: '2WcnJIVXlq2EYEbHWKr-7g',
    recipients: [{ encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ' }],
  };

  const uncompressedUnprotectedAttachedToken: GeneralJsonWebEncryptionToken = {
    unprotected: { alg: 'A128KW', enc: 'A128CBC-HS256', jku: 'https://server.example.com/keys.jwks', kid: '7' },
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    aad: '.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE',
    ciphertext: 'KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY',
    tag: 'W77Q108vf3uFnX_LmZPIlA',
    recipients: [{ encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ' }],
  };

  const uncompressedRecipientAttachedToken: GeneralJsonWebEncryptionToken = {
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    aad: '.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE',
    ciphertext: 'KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY',
    tag: 'W77Q108vf3uFnX_LmZPIlA',
    recipients: [
      {
        header: { alg: 'A128KW', enc: 'A128CBC-HS256', jku: 'https://server.example.com/keys.jwks', kid: '7' },
        encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
      },
    ],
  };

  const uncompressedProtectedAndUnprotectedAttachedToken: GeneralJsonWebEncryptionToken = {
    protected: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    unprotected: { alg: 'A128KW', jku: 'https://server.example.com/keys.jwks', kid: '7' },
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    aad: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE',
    ciphertext: 'KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY',
    tag: 'ULYMNP5lrIthBrdvAIzyqg',
    recipients: [{ encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ' }],
  };

  const uncompressedProtectedAndRecipientAttachedToken: GeneralJsonWebEncryptionToken = {
    protected: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    aad: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE',
    ciphertext: 'KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY',
    tag: 'ULYMNP5lrIthBrdvAIzyqg',
    recipients: [
      {
        header: { alg: 'A128KW', jku: 'https://server.example.com/keys.jwks', kid: '7' },
        encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
      },
    ],
  };

  const uncompressedUnprotectedAndRecipientAttachedToken: GeneralJsonWebEncryptionToken = {
    unprotected: { enc: 'A128CBC-HS256' },
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    aad: '.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE',
    ciphertext: 'KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY',
    tag: 'W77Q108vf3uFnX_LmZPIlA',
    recipients: [
      {
        header: { alg: 'A128KW', jku: 'https://server.example.com/keys.jwks', kid: '7' },
        encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
      },
    ],
  };

  const uncompressedFullAttachedToken: GeneralJsonWebEncryptionToken = {
    protected: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    unprotected: { jku: 'https://server.example.com/keys.jwks' },
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    aad: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE',
    ciphertext: 'KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY',
    tag: 'ULYMNP5lrIthBrdvAIzyqg',
    recipients: [
      { header: { alg: 'A128KW', kid: '7' }, encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ' },
    ],
  };
  // #endregion
  // #region Uncompressed Detached Token with Additional Authenticated Data
  const uncompressedProtectedDetachedToken: GeneralJsonWebEncryptionToken = {
    protected:
      'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyJ9',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    aad:
      'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyJ9.' +
      'YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE',
    tag: '2WcnJIVXlq2EYEbHWKr-7g',
    recipients: [{ encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ' }],
  };

  const uncompressedUnprotectedDetachedToken: GeneralJsonWebEncryptionToken = {
    unprotected: { alg: 'A128KW', enc: 'A128CBC-HS256', jku: 'https://server.example.com/keys.jwks', kid: '7' },
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    aad: '.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE',
    tag: 'W77Q108vf3uFnX_LmZPIlA',
    recipients: [{ encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ' }],
  };

  const uncompressedRecipientDetachedToken: GeneralJsonWebEncryptionToken = {
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    aad: '.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE',
    tag: 'W77Q108vf3uFnX_LmZPIlA',
    recipients: [
      {
        header: { alg: 'A128KW', enc: 'A128CBC-HS256', jku: 'https://server.example.com/keys.jwks', kid: '7' },
        encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
      },
    ],
  };

  const uncompressedProtectedAndUnprotectedDetachedToken: GeneralJsonWebEncryptionToken = {
    protected: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    unprotected: { alg: 'A128KW', jku: 'https://server.example.com/keys.jwks', kid: '7' },
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    aad: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE',
    tag: 'ULYMNP5lrIthBrdvAIzyqg',
    recipients: [{ encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ' }],
  };

  const uncompressedProtectedAndRecipientDetachedToken: GeneralJsonWebEncryptionToken = {
    protected: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    aad: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE',
    tag: 'ULYMNP5lrIthBrdvAIzyqg',
    recipients: [
      {
        header: { alg: 'A128KW', jku: 'https://server.example.com/keys.jwks', kid: '7' },
        encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
      },
    ],
  };

  const uncompressedUnprotectedAndRecipientDetachedToken: GeneralJsonWebEncryptionToken = {
    unprotected: { enc: 'A128CBC-HS256' },
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    aad: '.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE',
    tag: 'W77Q108vf3uFnX_LmZPIlA',
    recipients: [
      {
        header: { alg: 'A128KW', jku: 'https://server.example.com/keys.jwks', kid: '7' },
        encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
      },
    ],
  };

  const uncompressedFullDetachedToken: GeneralJsonWebEncryptionToken = {
    protected: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    unprotected: { jku: 'https://server.example.com/keys.jwks' },
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    aad: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE',
    tag: 'ULYMNP5lrIthBrdvAIzyqg',
    recipients: [
      { header: { alg: 'A128KW', kid: '7' }, encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ' },
    ],
  };
  // #endregion
  // #region Compressed Attached Token with Additional Authenticated Data
  const compressedProtectedAttachedToken: GeneralJsonWebEncryptionToken = {
    protected:
      'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiemlwIjoiREVGIiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyJ9',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    aad:
      'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiemlwIjoiREVGIiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyJ9.' +
      'YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE',
    ciphertext: '7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA',
    tag: 'SRoHlcdRqnsVScLWNZIwtA',
    recipients: [{ encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ' }],
  };

  const compressedUnprotectedAttachedToken: GeneralJsonWebEncryptionToken = {
    unprotected: {
      alg: 'A128KW',
      enc: 'A128CBC-HS256',
      zip: 'DEF',
      jku: 'https://server.example.com/keys.jwks',
      kid: '7',
    },
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    aad: '.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE',
    ciphertext: '7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA',
    tag: '0Z9lyKxM6Rz-6zCUcfNOmQ',
    recipients: [{ encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ' }],
  };

  const compressedRecipientAttachedToken: GeneralJsonWebEncryptionToken = {
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    aad: '.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE',
    ciphertext: '7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA',
    tag: '0Z9lyKxM6Rz-6zCUcfNOmQ',
    recipients: [
      {
        header: {
          alg: 'A128KW',
          enc: 'A128CBC-HS256',
          zip: 'DEF',
          jku: 'https://server.example.com/keys.jwks',
          kid: '7',
        },
        encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
      },
    ],
  };

  const compressedProtectedAndUnprotectedAttachedToken: GeneralJsonWebEncryptionToken = {
    protected: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    unprotected: { alg: 'A128KW', zip: 'DEF', jku: 'https://server.example.com/keys.jwks', kid: '7' },
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    aad: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE',
    ciphertext: '7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA',
    tag: '1IIFfjlJQ4EkqwKhBdlY5w',
    recipients: [{ encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ' }],
  };

  const compressedProtectedAndRecipientAttachedToken: GeneralJsonWebEncryptionToken = {
    protected: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    aad: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE',
    ciphertext: '7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA',
    tag: '1IIFfjlJQ4EkqwKhBdlY5w',
    recipients: [
      {
        header: { alg: 'A128KW', zip: 'DEF', jku: 'https://server.example.com/keys.jwks', kid: '7' },
        encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
      },
    ],
  };

  const compressedUnprotectedAndRecipientAttachedToken: GeneralJsonWebEncryptionToken = {
    unprotected: { enc: 'A128CBC-HS256' },
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    aad: '.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE',
    ciphertext: '7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA',
    tag: '0Z9lyKxM6Rz-6zCUcfNOmQ',
    recipients: [
      {
        header: { alg: 'A128KW', zip: 'DEF', jku: 'https://server.example.com/keys.jwks', kid: '7' },
        encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
      },
    ],
  };

  const compressedFullAttachedToken: GeneralJsonWebEncryptionToken = {
    protected: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    unprotected: { jku: 'https://server.example.com/keys.jwks' },
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    aad: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE',
    ciphertext: '7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA',
    tag: '1IIFfjlJQ4EkqwKhBdlY5w',
    recipients: [
      {
        header: { alg: 'A128KW', zip: 'DEF', kid: '7' },
        encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
      },
    ],
  };
  // #endregion
  // #region Compressed Detached Token with Additional Authenticated Data
  const compressedProtectedDetachedToken: GeneralJsonWebEncryptionToken = {
    protected:
      'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiemlwIjoiREVGIiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyJ9',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    aad:
      'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiemlwIjoiREVGIiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyJ9.' +
      'YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE',
    tag: 'SRoHlcdRqnsVScLWNZIwtA',
    recipients: [{ encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ' }],
  };

  const compressedUnprotectedDetachedToken: GeneralJsonWebEncryptionToken = {
    unprotected: {
      alg: 'A128KW',
      enc: 'A128CBC-HS256',
      zip: 'DEF',
      jku: 'https://server.example.com/keys.jwks',
      kid: '7',
    },
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    aad: '.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE',
    tag: '0Z9lyKxM6Rz-6zCUcfNOmQ',
    recipients: [{ encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ' }],
  };

  const compressedRecipientDetachedToken: GeneralJsonWebEncryptionToken = {
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    aad: '.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE',
    tag: '0Z9lyKxM6Rz-6zCUcfNOmQ',
    recipients: [
      {
        header: {
          alg: 'A128KW',
          enc: 'A128CBC-HS256',
          zip: 'DEF',
          jku: 'https://server.example.com/keys.jwks',
          kid: '7',
        },
        encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
      },
    ],
  };

  const compressedProtectedAndUnprotectedDetachedToken: GeneralJsonWebEncryptionToken = {
    protected: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    unprotected: { alg: 'A128KW', zip: 'DEF', jku: 'https://server.example.com/keys.jwks', kid: '7' },
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    aad: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE',
    tag: '1IIFfjlJQ4EkqwKhBdlY5w',
    recipients: [{ encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ' }],
  };

  const compressedProtectedAndRecipientDetachedToken: GeneralJsonWebEncryptionToken = {
    protected: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    aad: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE',
    tag: '1IIFfjlJQ4EkqwKhBdlY5w',
    recipients: [
      {
        header: { alg: 'A128KW', zip: 'DEF', jku: 'https://server.example.com/keys.jwks', kid: '7' },
        encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
      },
    ],
  };

  const compressedUnprotectedAndRecipientDetachedToken: GeneralJsonWebEncryptionToken = {
    unprotected: { enc: 'A128CBC-HS256' },
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    aad: '.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE',
    tag: '0Z9lyKxM6Rz-6zCUcfNOmQ',
    recipients: [
      {
        header: { alg: 'A128KW', zip: 'DEF', jku: 'https://server.example.com/keys.jwks', kid: '7' },
        encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
      },
    ],
  };

  const compressedFullDetachedToken: GeneralJsonWebEncryptionToken = {
    protected: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    unprotected: { jku: 'https://server.example.com/keys.jwks' },
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    aad: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE',
    tag: '1IIFfjlJQ4EkqwKhBdlY5w',
    recipients: [
      {
        header: { alg: 'A128KW', zip: 'DEF', kid: '7' },
        encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
      },
    ],
  };
  // #endregion

  const plaintext = Buffer.from('Live long and prosper.');

  const encHeader: Partial<JsonWebEncryptionHeaderParameters> = { enc: 'A128CBC-HS256' };
  const jkuHeader: Partial<JsonWebEncryptionHeaderParameters> = { jku: 'https://server.example.com/keys.jwks' };
  const algEncKidHeader: Partial<JsonWebEncryptionHeaderParameters> = { alg: 'A128KW', enc: 'A128CBC-HS256', kid: '7' };
  const algKidHeader: Partial<JsonWebEncryptionHeaderParameters> = { alg: 'A128KW', kid: '7' };
  const algZipKidHeader: Partial<JsonWebEncryptionHeaderParameters> = {
    alg: 'A128KW',
    zip: 'DEF',
    kid: '7',
  };
  const algJkuKidHeader: Partial<JsonWebEncryptionHeaderParameters> = {
    alg: 'A128KW',
    jku: 'https://server.example.com/keys.jwks',
    kid: '7',
  };
  const algEncJkuKidHeader: Partial<JsonWebEncryptionHeaderParameters> = {
    alg: 'A128KW',
    enc: 'A128CBC-HS256',
    jku: 'https://server.example.com/keys.jwks',
    kid: '7',
  };
  const algZipJkuKidHeader: Partial<JsonWebEncryptionHeaderParameters> = {
    alg: 'A128KW',
    zip: 'DEF',
    jku: 'https://server.example.com/keys.jwks',
    kid: '7',
  };
  const algEncZipJkuKidHeader: Partial<JsonWebEncryptionHeaderParameters> = {
    alg: 'A128KW',
    enc: 'A128CBC-HS256',
    zip: 'DEF',
    jku: 'https://server.example.com/keys.jwks',
    kid: '7',
  };

  const initializationVector = Buffer.from('AxY8DCtDaGlsbGljb3RoZQ', 'base64url');
  const additionalAuthenticatedData = Buffer.from('YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE', 'base64url');

  const jwk = new OctetSequenceJsonWebKey({ kty: 'oct', k: 'GawgguFyGrWKav7AX4VKUg', kid: '7' });

  beforeEach(() => {
    https.get = jest.fn().mockImplementation((_, cb) => {
      const stream = new Stream();
      cb(stream);
      stream.emit('data', jsonStringify({ keys: [jwk.parameters] }));
      stream.emit('end');
    });
  });

  beforeEach(() => {
    jest
      .spyOn(AESCBCJsonWebEncryptionContentEncryptionBackend.prototype, 'generateInitializationVector')
      .mockResolvedValueOnce(initializationVector);
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it.each(invalidPlaintexts)('should throw when the provided Plaintext is invalid.', async (plaintext) => {
    await expect(
      serialize(plaintext, {
        protectedHeader: encHeader,
        unprotectedHeader: jkuHeader,
        recipients: [{ recipientUnprotectedHeader: algKidHeader }],
      }),
    ).rejects.toThrowWithMessage(TypeError, 'The provided Plaintext is invalid.');
  });

  it.each(invalidProtectedHeaders)(
    'should throw when the provided JSON Web Encryption Protected Header is invalid.',
    async (protectedHeader) => {
      await expect(
        serialize(plaintext, {
          protectedHeader,
          unprotectedHeader: jkuHeader,
          recipients: [{ recipientUnprotectedHeader: algKidHeader }],
        }),
      ).rejects.toThrowWithMessage(TypeError, 'The provided JSON Web Encryption Protected Header is invalid.');
    },
  );

  it.each(invalidUnprotectedHeaders)(
    'should throw when the provided JSON Web Encryption Unprotected Header is invalid',
    async (unprotectedHeader) => {
      await expect(
        serialize(plaintext, {
          protectedHeader: encHeader,
          unprotectedHeader,
          recipients: [{ recipientUnprotectedHeader: algKidHeader }],
        }),
      ).rejects.toThrowWithMessage(TypeError, 'The provided JSON Web Encryption Unprotected Header is invalid.');
    },
  );

  it.each(invalidRecipients)(
    'should throw when the provided JSON Web Encryption Recipients is invalid.',
    async (recipients) => {
      await expect(
        serialize(plaintext, { protectedHeader: encHeader, unprotectedHeader: jkuHeader, recipients }),
      ).rejects.toThrowWithMessage(TypeError, 'The provided JSON Web Encryption Recipients is invalid.');
    },
  );

  it.each(invalidRecipientUnprotectedHeaders)(
    'should throw when the provided JSON Web Encryption Recipient Unprotected Header is invalid',
    async (recipientUnprotectedHeader) => {
      await expect(
        serialize(plaintext, {
          protectedHeader: encHeader,
          unprotectedHeader: jkuHeader,
          recipients: [{ recipientUnprotectedHeader }],
        }),
      ).rejects.toThrowWithMessage(
        TypeError,
        'The provided JSON Web Encryption Recipient Unprotected Header is invalid.',
      );
    },
  );

  it('should throw when no JSON Web Encryption Header is provided.', async () => {
    await expect(serialize(plaintext, { recipients: [{}] })).rejects.toThrowWithMessage(
      InvalidJoseHeaderError,
      'Missing at least one required JSON Web Encryption Header.',
    );
  });

  it.each(repeatedJoseHeaderParameters)(
    'should throw when there are repeated JSON Web Encryption Header Parameters.',
    async (protectedHeader, unprotectedHeader, recipientUnprotectedHeader) => {
      await expect(
        serialize(plaintext, { protectedHeader, unprotectedHeader, recipients: [{ recipientUnprotectedHeader }] }),
      ).rejects.toThrowWithMessage(
        InvalidJoseHeaderError,
        'Cannot have repeated JSON Web Encryption Header Parameters.',
      );
    },
  );

  it.each(forbiddenKeyManagementAlgorithms)(
    'should throw when providing a forbidden JSON Web Encryption Key Management Algorithm.',
    async (alg) => {
      await expect(
        serialize(plaintext, {
          protectedHeader: encHeader,
          unprotectedHeader: jkuHeader,
          recipients: [{ recipientUnprotectedHeader: { ...algKidHeader, alg } }],
        }),
      ).rejects.toThrowWithMessage(
        InvalidJoseHeaderError,
        'Cannot use the JSON Web Encryption Key Management Algorithms "ECDH-ES" and "dir" with General JSON Web Encryption Serializations.',
      );
    },
  );

  it('should throw when providing more than one JSON Web Encryption Content Encryption Algorithms.', async () => {
    await expect(
      serialize(plaintext, {
        protectedHeader: algKidHeader,
        unprotectedHeader: jkuHeader,
        recipients: [
          { recipientUnprotectedHeader: { enc: 'A128CBC-HS256' } },
          { recipientUnprotectedHeader: { enc: 'A128GCM' } },
        ],
      }),
    ).rejects.toThrowWithMessage(
      InvalidJoseHeaderError,
      'Cannot have distinct JSON Web Encryption Content Encryption Algorithms.',
    );
  });

  it('should throw when providing more than one JSON Web Encryption Compression Algorithms.', async () => {
    await expect(
      serialize(plaintext, {
        protectedHeader: algEncKidHeader,
        unprotectedHeader: jkuHeader,
        recipients: [{ recipientUnprotectedHeader: {} }, { recipientUnprotectedHeader: { zip: 'DEF' } }],
      }),
    ).rejects.toThrowWithMessage(
      InvalidJoseHeaderError,
      'Cannot have distinct JSON Web Encryption Compression Algorithms.',
    );
  });

  it.each(invalidSerializeOptions)('should throw when the provided options is invalid.', async (options) => {
    await expect(
      serialize(
        plaintext,
        {
          protectedHeader: encHeader,
          unprotectedHeader: jkuHeader,
          recipients: [{ recipientUnprotectedHeader: algKidHeader }],
        },
        options,
      ),
    ).rejects.toThrowWithMessage(TypeError, 'The provided options is invalid.');
  });

  it.each(invalidAads)('should throw when the provided option "aad" is invalid.', async (aad) => {
    await expect(
      serialize(
        plaintext,
        {
          protectedHeader: encHeader,
          unprotectedHeader: jkuHeader,
          recipients: [{ recipientUnprotectedHeader: algKidHeader }],
        },
        { aad },
      ),
    ).rejects.toThrowWithMessage(TypeError, 'The provided option "aad" is invalid.');
  });

  it.each(invalidJwks)('should throw when the provided option "jwks" is invalid.', async (jwks) => {
    await expect(
      serialize(
        plaintext,
        {
          protectedHeader: encHeader,
          unprotectedHeader: jkuHeader,
          recipients: [{ recipientUnprotectedHeader: algKidHeader }],
        },
        { jwks },
      ),
    ).rejects.toThrowWithMessage(TypeError, 'The provided option "jwks" is invalid.');
  });

  it.each(invalidDetacheds)('should throw when the provided option "detached" is invalid.', async (detached) => {
    await expect(
      serialize(
        plaintext,
        {
          protectedHeader: encHeader,
          unprotectedHeader: jkuHeader,
          recipients: [{ recipientUnprotectedHeader: algKidHeader }],
        },
        { detached },
      ),
    ).rejects.toThrowWithMessage(TypeError, 'The provided option "detached" is invalid.');
  });

  it('should throw when failing to serialize the provided General JSON Web Encryption.', async () => {
    await expect(
      serialize(plaintext, { protectedHeader: encHeader, recipients: [{ recipientUnprotectedHeader: algKidHeader }] }),
    ).rejects.toThrow();
  });

  it('should serialize a General JSON Web Encryption into an Uncompressed Protected Attached Token with no Additional Authenticated Data.', async () => {
    await expect(
      serialize(plaintext, { protectedHeader: algEncJkuKidHeader, recipients: [{}] }, { jwks: [jwk] }),
    ).resolves.toStrictEqual(uncompressedProtectedAttachedTokenNoAad);
  });

  it('should serialize a General JSON Web Encryption into an Uncompressed Unprotected Attached Token with no Additional Authenticated Data.', async () => {
    await expect(
      serialize(plaintext, { unprotectedHeader: algEncJkuKidHeader, recipients: [{}] }, { jwks: [jwk] }),
    ).resolves.toStrictEqual(uncompressedUnprotectedAttachedTokenNoAad);
  });

  it('should serialize a General JSON Web Encryption into an Uncompressed Recipient Attached Token with no Additional Authenticated Data.', async () => {
    await expect(
      serialize(plaintext, { recipients: [{ recipientUnprotectedHeader: algEncJkuKidHeader }] }, { jwks: [jwk] }),
    ).resolves.toStrictEqual(uncompressedRecipientAttachedTokenNoAad);
  });

  it('should serialize a General JSON Web Encryption into an Uncompressed Protected and Unprotected Attached Token with no Additional Authenticated Data.', async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: encHeader, unprotectedHeader: algJkuKidHeader, recipients: [{}] },
        { jwks: [jwk] },
      ),
    ).resolves.toStrictEqual(uncompressedProtectedAndUnprotectedAttachedTokenNoAad);
  });

  it('should serialize a General JSON Web Encryption into an Uncompressed Protected and Recipient Attached Token with no Additional Authenticated Data.', async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: encHeader, recipients: [{ recipientUnprotectedHeader: algJkuKidHeader }] },
        { jwks: [jwk] },
      ),
    ).resolves.toStrictEqual(uncompressedProtectedAndRecipientAttachedTokenNoAad);
  });

  it('should serialize a General JSON Web Encryption into an Uncompressed Unprotected and Recipient Attached Token with no Additional Authenticated Data.', async () => {
    await expect(
      serialize(
        plaintext,
        { unprotectedHeader: encHeader, recipients: [{ recipientUnprotectedHeader: algJkuKidHeader }] },
        { jwks: [jwk] },
      ),
    ).resolves.toStrictEqual(uncompressedUnprotectedAndRecipientAttachedTokenNoAad);
  });

  it('should serialize a General JSON Web Encryption into an Uncompressed Protected, Unprotected and Recipient Attached Token with no Additional Authenticated Data.', async () => {
    await expect(
      serialize(
        plaintext,
        {
          protectedHeader: encHeader,
          unprotectedHeader: jkuHeader,
          recipients: [{ recipientUnprotectedHeader: algKidHeader }],
        },
        { jwks: [jwk] },
      ),
    ).resolves.toStrictEqual(uncompressedFullAttachedTokenNoAad);
  });

  it('should serialize a General JSON Web Encryption into an Uncompressed Protected Detached Token with no Additional Authenticated Data.', async () => {
    await expect(
      serialize(plaintext, { protectedHeader: algEncJkuKidHeader, recipients: [{}] }, { jwks: [jwk], detached: true }),
    ).resolves.toStrictEqual(uncompressedProtectedDetachedTokenNoAad);
  });

  it('should serialize a General JSON Web Encryption into an Uncompressed Unprotected Detached Token with no Additional Authenticated Data.', async () => {
    await expect(
      serialize(
        plaintext,
        { unprotectedHeader: algEncJkuKidHeader, recipients: [{}] },
        { jwks: [jwk], detached: true },
      ),
    ).resolves.toStrictEqual(uncompressedUnprotectedDetachedTokenNoAad);
  });

  it('should serialize a General JSON Web Encryption into an Uncompressed Recipient Detached Token with no Additional Authenticated Data.', async () => {
    await expect(
      serialize(
        plaintext,
        { recipients: [{ recipientUnprotectedHeader: algEncJkuKidHeader }] },
        { jwks: [jwk], detached: true },
      ),
    ).resolves.toStrictEqual(uncompressedRecipientDetachedTokenNoAad);
  });

  it('should serialize a General JSON Web Encryption into an Uncompressed Protected and Unprotected Detached Token with no Additional Authenticated Data.', async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: encHeader, unprotectedHeader: algJkuKidHeader, recipients: [{}] },
        { jwks: [jwk], detached: true },
      ),
    ).resolves.toStrictEqual(uncompressedProtectedAndUnprotectedDetachedTokenNoAad);
  });

  it('should serialize a General JSON Web Encryption into an Uncompressed Protected and Recipient Detached Token with no Additional Authenticated Data.', async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: encHeader, recipients: [{ recipientUnprotectedHeader: algJkuKidHeader }] },
        { jwks: [jwk], detached: true },
      ),
    ).resolves.toStrictEqual(uncompressedProtectedAndRecipientDetachedTokenNoAad);
  });

  it('should serialize a General JSON Web Encryption into an Uncompressed Unprotected and Recipient Detached Token with no Additional Authenticated Data.', async () => {
    await expect(
      serialize(
        plaintext,
        { unprotectedHeader: encHeader, recipients: [{ recipientUnprotectedHeader: algJkuKidHeader }] },
        { jwks: [jwk], detached: true },
      ),
    ).resolves.toStrictEqual(uncompressedUnprotectedAndRecipientDetachedTokenNoAad);
  });

  it('should serialize a General JSON Web Encryption into an Uncompressed Protected, Unprotected and Recipient Detached Token with no Additional Authenticated Data.', async () => {
    await expect(
      serialize(
        plaintext,
        {
          protectedHeader: encHeader,
          unprotectedHeader: jkuHeader,
          recipients: [{ recipientUnprotectedHeader: algKidHeader }],
        },
        { jwks: [jwk], detached: true },
      ),
    ).resolves.toStrictEqual(uncompressedFullDetachedTokenNoAad);
  });

  it('should serialize a General JSON Web Encryption into an compressed Protected Attached Token with no Additional Authenticated Data.', async () => {
    await expect(
      serialize(plaintext, { protectedHeader: algEncZipJkuKidHeader, recipients: [{}] }, { jwks: [jwk] }),
    ).resolves.toStrictEqual(compressedProtectedAttachedTokenNoAad);
  });

  it('should serialize a General JSON Web Encryption into an compressed Unprotected Attached Token with no Additional Authenticated Data.', async () => {
    await expect(
      serialize(plaintext, { unprotectedHeader: algEncZipJkuKidHeader, recipients: [{}] }, { jwks: [jwk] }),
    ).resolves.toStrictEqual(compressedUnprotectedAttachedTokenNoAad);
  });

  it('should serialize a General JSON Web Encryption into an compressed Recipient Attached Token with no Additional Authenticated Data.', async () => {
    await expect(
      serialize(plaintext, { recipients: [{ recipientUnprotectedHeader: algEncZipJkuKidHeader }] }, { jwks: [jwk] }),
    ).resolves.toStrictEqual(compressedRecipientAttachedTokenNoAad);
  });

  it('should serialize a General JSON Web Encryption into an compressed Protected and Unprotected Attached Token with no Additional Authenticated Data.', async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: encHeader, unprotectedHeader: algZipJkuKidHeader, recipients: [{}] },
        { jwks: [jwk] },
      ),
    ).resolves.toStrictEqual(compressedProtectedAndUnprotectedAttachedTokenNoAad);
  });

  it('should serialize a General JSON Web Encryption into an compressed Protected and Recipient Attached Token with no Additional Authenticated Data.', async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: encHeader, recipients: [{ recipientUnprotectedHeader: algZipJkuKidHeader }] },
        { jwks: [jwk] },
      ),
    ).resolves.toStrictEqual(compressedProtectedAndRecipientAttachedTokenNoAad);
  });

  it('should serialize a General JSON Web Encryption into an compressed Unprotected and Recipient Attached Token with no Additional Authenticated Data.', async () => {
    await expect(
      serialize(
        plaintext,
        { unprotectedHeader: encHeader, recipients: [{ recipientUnprotectedHeader: algZipJkuKidHeader }] },
        { jwks: [jwk] },
      ),
    ).resolves.toStrictEqual(compressedUnprotectedAndRecipientAttachedTokenNoAad);
  });

  it('should serialize a General JSON Web Encryption into an compressed Protected, Unprotected and Recipient Attached Token with no Additional Authenticated Data.', async () => {
    await expect(
      serialize(
        plaintext,
        {
          protectedHeader: encHeader,
          unprotectedHeader: jkuHeader,
          recipients: [{ recipientUnprotectedHeader: algZipKidHeader }],
        },
        { jwks: [jwk] },
      ),
    ).resolves.toStrictEqual(compressedFullAttachedTokenNoAad);
  });

  it('should serialize a General JSON Web Encryption into an compressed Protected Detached Token with no Additional Authenticated Data.', async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: algEncZipJkuKidHeader, recipients: [{}] },
        { jwks: [jwk], detached: true },
      ),
    ).resolves.toStrictEqual(compressedProtectedDetachedTokenNoAad);
  });

  it('should serialize a General JSON Web Encryption into an compressed Unprotected Detached Token with no Additional Authenticated Data.', async () => {
    await expect(
      serialize(
        plaintext,
        { unprotectedHeader: algEncZipJkuKidHeader, recipients: [{}] },
        { jwks: [jwk], detached: true },
      ),
    ).resolves.toStrictEqual(compressedUnprotectedDetachedTokenNoAad);
  });

  it('should serialize a General JSON Web Encryption into an compressed Recipient Detached Token with no Additional Authenticated Data.', async () => {
    await expect(
      serialize(
        plaintext,
        { recipients: [{ recipientUnprotectedHeader: algEncZipJkuKidHeader }] },
        { jwks: [jwk], detached: true },
      ),
    ).resolves.toStrictEqual(compressedRecipientDetachedTokenNoAad);
  });

  it('should serialize a General JSON Web Encryption into an compressed Protected and Unprotected Detached Token with no Additional Authenticated Data.', async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: encHeader, unprotectedHeader: algZipJkuKidHeader, recipients: [{}] },
        { jwks: [jwk], detached: true },
      ),
    ).resolves.toStrictEqual(compressedProtectedAndUnprotectedDetachedTokenNoAad);
  });

  it('should serialize a General JSON Web Encryption into an compressed Protected and Recipient Detached Token with no Additional Authenticated Data.', async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: encHeader, recipients: [{ recipientUnprotectedHeader: algZipJkuKidHeader }] },
        { jwks: [jwk], detached: true },
      ),
    ).resolves.toStrictEqual(compressedProtectedAndRecipientDetachedTokenNoAad);
  });

  it('should serialize a General JSON Web Encryption into an compressed Unprotected and Recipient Detached Token with no Additional Authenticated Data.', async () => {
    await expect(
      serialize(
        plaintext,
        { unprotectedHeader: encHeader, recipients: [{ recipientUnprotectedHeader: algZipJkuKidHeader }] },
        { jwks: [jwk], detached: true },
      ),
    ).resolves.toStrictEqual(compressedUnprotectedAndRecipientDetachedTokenNoAad);
  });

  it('should serialize a General JSON Web Encryption into an compressed Protected, Unprotected and Recipient Detached Token with no Additional Authenticated Data.', async () => {
    await expect(
      serialize(
        plaintext,
        {
          protectedHeader: encHeader,
          unprotectedHeader: jkuHeader,
          recipients: [{ recipientUnprotectedHeader: algZipKidHeader }],
        },
        { jwks: [jwk], detached: true },
      ),
    ).resolves.toStrictEqual(compressedFullDetachedTokenNoAad);
  });

  it('should serialize a General JSON Web Encryption into an Uncompressed Protected Attached Token with Additional Authenticated Data.', async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: algEncJkuKidHeader, recipients: [{}] },
        { aad: additionalAuthenticatedData, jwks: [jwk] },
      ),
    ).resolves.toStrictEqual(uncompressedProtectedAttachedToken);
  });

  it('should serialize a General JSON Web Encryption into an Uncompressed Unprotected Attached Token with Additional Authenticated Data.', async () => {
    await expect(
      serialize(
        plaintext,
        { unprotectedHeader: algEncJkuKidHeader, recipients: [{}] },
        { aad: additionalAuthenticatedData, jwks: [jwk] },
      ),
    ).resolves.toStrictEqual(uncompressedUnprotectedAttachedToken);
  });

  it('should serialize a General JSON Web Encryption into an Uncompressed Recipient Attached Token with Additional Authenticated Data.', async () => {
    await expect(
      serialize(
        plaintext,
        { recipients: [{ recipientUnprotectedHeader: algEncJkuKidHeader }] },
        { aad: additionalAuthenticatedData, jwks: [jwk] },
      ),
    ).resolves.toStrictEqual(uncompressedRecipientAttachedToken);
  });

  it('should serialize a General JSON Web Encryption into an Uncompressed Protected and Unprotected Attached Token with Additional Authenticated Data.', async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: encHeader, unprotectedHeader: algJkuKidHeader, recipients: [{}] },
        { aad: additionalAuthenticatedData, jwks: [jwk] },
      ),
    ).resolves.toStrictEqual(uncompressedProtectedAndUnprotectedAttachedToken);
  });

  it('should serialize a General JSON Web Encryption into an Uncompressed Protected and Recipient Attached Token with Additional Authenticated Data.', async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: encHeader, recipients: [{ recipientUnprotectedHeader: algJkuKidHeader }] },
        { aad: additionalAuthenticatedData, jwks: [jwk] },
      ),
    ).resolves.toStrictEqual(uncompressedProtectedAndRecipientAttachedToken);
  });

  it('should serialize a General JSON Web Encryption into an Uncompressed Unprotected and Recipient Attached Token with Additional Authenticated Data.', async () => {
    await expect(
      serialize(
        plaintext,
        { unprotectedHeader: encHeader, recipients: [{ recipientUnprotectedHeader: algJkuKidHeader }] },
        { aad: additionalAuthenticatedData, jwks: [jwk] },
      ),
    ).resolves.toStrictEqual(uncompressedUnprotectedAndRecipientAttachedToken);
  });

  it('should serialize a General JSON Web Encryption into an Uncompressed Protected, Unprotected and Recipient Attached Token with Additional Authenticated Data.', async () => {
    await expect(
      serialize(
        plaintext,
        {
          protectedHeader: encHeader,
          unprotectedHeader: jkuHeader,
          recipients: [{ recipientUnprotectedHeader: algKidHeader }],
        },
        { aad: additionalAuthenticatedData, jwks: [jwk] },
      ),
    ).resolves.toStrictEqual(uncompressedFullAttachedToken);
  });

  it('should serialize a General JSON Web Encryption into an Uncompressed Protected Detached Token with Additional Authenticated Data.', async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: algEncJkuKidHeader, recipients: [{}] },
        { aad: additionalAuthenticatedData, jwks: [jwk], detached: true },
      ),
    ).resolves.toStrictEqual(uncompressedProtectedDetachedToken);
  });

  it('should serialize a General JSON Web Encryption into an Uncompressed Unprotected Detached Token with Additional Authenticated Data.', async () => {
    await expect(
      serialize(
        plaintext,
        { unprotectedHeader: algEncJkuKidHeader, recipients: [{}] },
        { aad: additionalAuthenticatedData, jwks: [jwk], detached: true },
      ),
    ).resolves.toStrictEqual(uncompressedUnprotectedDetachedToken);
  });

  it('should serialize a General JSON Web Encryption into an Uncompressed Recipient Detached Token with Additional Authenticated Data.', async () => {
    await expect(
      serialize(
        plaintext,
        { recipients: [{ recipientUnprotectedHeader: algEncJkuKidHeader }] },
        { aad: additionalAuthenticatedData, jwks: [jwk], detached: true },
      ),
    ).resolves.toStrictEqual(uncompressedRecipientDetachedToken);
  });

  it('should serialize a General JSON Web Encryption into an Uncompressed Protected and Unprotected Detached Token with Additional Authenticated Data.', async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: encHeader, unprotectedHeader: algJkuKidHeader, recipients: [{}] },
        { aad: additionalAuthenticatedData, jwks: [jwk], detached: true },
      ),
    ).resolves.toStrictEqual(uncompressedProtectedAndUnprotectedDetachedToken);
  });

  it('should serialize a General JSON Web Encryption into an Uncompressed Protected and Recipient Detached Token with Additional Authenticated Data.', async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: encHeader, recipients: [{ recipientUnprotectedHeader: algJkuKidHeader }] },
        { aad: additionalAuthenticatedData, jwks: [jwk], detached: true },
      ),
    ).resolves.toStrictEqual(uncompressedProtectedAndRecipientDetachedToken);
  });

  it('should serialize a General JSON Web Encryption into an Uncompressed Unprotected and Recipient Detached Token with Additional Authenticated Data.', async () => {
    await expect(
      serialize(
        plaintext,
        { unprotectedHeader: encHeader, recipients: [{ recipientUnprotectedHeader: algJkuKidHeader }] },
        { aad: additionalAuthenticatedData, jwks: [jwk], detached: true },
      ),
    ).resolves.toStrictEqual(uncompressedUnprotectedAndRecipientDetachedToken);
  });

  it('should serialize a General JSON Web Encryption into an Uncompressed Protected, Unprotected and Recipient Detached Token with Additional Authenticated Data.', async () => {
    await expect(
      serialize(
        plaintext,
        {
          protectedHeader: encHeader,
          unprotectedHeader: jkuHeader,
          recipients: [{ recipientUnprotectedHeader: algKidHeader }],
        },
        { aad: additionalAuthenticatedData, jwks: [jwk], detached: true },
      ),
    ).resolves.toStrictEqual(uncompressedFullDetachedToken);
  });

  it('should serialize a General JSON Web Encryption into an compressed Protected Attached Token with Additional Authenticated Data.', async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: algEncZipJkuKidHeader, recipients: [{}] },
        { aad: additionalAuthenticatedData, jwks: [jwk] },
      ),
    ).resolves.toStrictEqual(compressedProtectedAttachedToken);
  });

  it('should serialize a General JSON Web Encryption into an compressed Unprotected Attached Token with Additional Authenticated Data.', async () => {
    await expect(
      serialize(
        plaintext,
        { unprotectedHeader: algEncZipJkuKidHeader, recipients: [{}] },
        { aad: additionalAuthenticatedData, jwks: [jwk] },
      ),
    ).resolves.toStrictEqual(compressedUnprotectedAttachedToken);
  });

  it('should serialize a General JSON Web Encryption into an compressed Recipient Attached Token with Additional Authenticated Data.', async () => {
    await expect(
      serialize(
        plaintext,
        { recipients: [{ recipientUnprotectedHeader: algEncZipJkuKidHeader }] },
        { aad: additionalAuthenticatedData, jwks: [jwk] },
      ),
    ).resolves.toStrictEqual(compressedRecipientAttachedToken);
  });

  it('should serialize a General JSON Web Encryption into an compressed Protected and Unprotected Attached Token with Additional Authenticated Data.', async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: encHeader, unprotectedHeader: algZipJkuKidHeader, recipients: [{}] },
        { aad: additionalAuthenticatedData, jwks: [jwk] },
      ),
    ).resolves.toStrictEqual(compressedProtectedAndUnprotectedAttachedToken);
  });

  it('should serialize a General JSON Web Encryption into an compressed Protected and Recipient Attached Token with Additional Authenticated Data.', async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: encHeader, recipients: [{ recipientUnprotectedHeader: algZipJkuKidHeader }] },
        { aad: additionalAuthenticatedData, jwks: [jwk] },
      ),
    ).resolves.toStrictEqual(compressedProtectedAndRecipientAttachedToken);
  });

  it('should serialize a General JSON Web Encryption into an compressed Unprotected and Recipient Attached Token with Additional Authenticated Data.', async () => {
    await expect(
      serialize(
        plaintext,
        { unprotectedHeader: encHeader, recipients: [{ recipientUnprotectedHeader: algZipJkuKidHeader }] },
        { aad: additionalAuthenticatedData, jwks: [jwk] },
      ),
    ).resolves.toStrictEqual(compressedUnprotectedAndRecipientAttachedToken);
  });

  it('should serialize a General JSON Web Encryption into an compressed Protected, Unprotected and Recipient Attached Token with Additional Authenticated Data.', async () => {
    await expect(
      serialize(
        plaintext,
        {
          protectedHeader: encHeader,
          unprotectedHeader: jkuHeader,
          recipients: [{ recipientUnprotectedHeader: algZipKidHeader }],
        },
        { aad: additionalAuthenticatedData, jwks: [jwk] },
      ),
    ).resolves.toStrictEqual(compressedFullAttachedToken);
  });

  it('should serialize a General JSON Web Encryption into an compressed Protected Detached Token with Additional Authenticated Data.', async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: algEncZipJkuKidHeader, recipients: [{}] },
        { aad: additionalAuthenticatedData, jwks: [jwk], detached: true },
      ),
    ).resolves.toStrictEqual(compressedProtectedDetachedToken);
  });

  it('should serialize a General JSON Web Encryption into an compressed Unprotected Detached Token with Additional Authenticated Data.', async () => {
    await expect(
      serialize(
        plaintext,
        { unprotectedHeader: algEncZipJkuKidHeader, recipients: [{}] },
        { aad: additionalAuthenticatedData, jwks: [jwk], detached: true },
      ),
    ).resolves.toStrictEqual(compressedUnprotectedDetachedToken);
  });

  it('should serialize a General JSON Web Encryption into an compressed Recipient Detached Token with Additional Authenticated Data.', async () => {
    await expect(
      serialize(
        plaintext,
        { recipients: [{ recipientUnprotectedHeader: algEncZipJkuKidHeader }] },
        { aad: additionalAuthenticatedData, jwks: [jwk], detached: true },
      ),
    ).resolves.toStrictEqual(compressedRecipientDetachedToken);
  });

  it('should serialize a General JSON Web Encryption into an compressed Protected and Unprotected Detached Token with Additional Authenticated Data.', async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: encHeader, unprotectedHeader: algZipJkuKidHeader, recipients: [{}] },
        { aad: additionalAuthenticatedData, jwks: [jwk], detached: true },
      ),
    ).resolves.toStrictEqual(compressedProtectedAndUnprotectedDetachedToken);
  });

  it('should serialize a General JSON Web Encryption into an compressed Protected and Recipient Detached Token with Additional Authenticated Data.', async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: encHeader, recipients: [{ recipientUnprotectedHeader: algZipJkuKidHeader }] },
        { aad: additionalAuthenticatedData, jwks: [jwk], detached: true },
      ),
    ).resolves.toStrictEqual(compressedProtectedAndRecipientDetachedToken);
  });

  it('should serialize a General JSON Web Encryption into an compressed Unprotected and Recipient Detached Token with Additional Authenticated Data.', async () => {
    await expect(
      serialize(
        plaintext,
        { unprotectedHeader: encHeader, recipients: [{ recipientUnprotectedHeader: algZipJkuKidHeader }] },
        { aad: additionalAuthenticatedData, jwks: [jwk], detached: true },
      ),
    ).resolves.toStrictEqual(compressedUnprotectedAndRecipientDetachedToken);
  });

  it('should serialize a General JSON Web Encryption into an compressed Protected, Unprotected and Recipient Detached Token with Additional Authenticated Data.', async () => {
    await expect(
      serialize(
        plaintext,
        {
          protectedHeader: encHeader,
          unprotectedHeader: jkuHeader,
          recipients: [{ recipientUnprotectedHeader: algZipKidHeader }],
        },
        { aad: additionalAuthenticatedData, jwks: [jwk], detached: true },
      ),
    ).resolves.toStrictEqual(compressedFullDetachedToken);
  });
});
