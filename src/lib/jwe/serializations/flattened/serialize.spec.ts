import { Buffer } from 'buffer';
import https from 'https';
import { Stream } from 'stream';

import { jsonStringify } from '@guarani/primitives';

import { InvalidJoseHeaderError } from '../../../errors/invalid-jose-header.error';
import { AESKWJsonWebEncryptionKeyManagementBackend } from '../../../jwa/jwe/alg/aeskw/aeskw-jsonwebencryption-key-management.backend';
import { AESCBCJsonWebEncryptionContentEncryptionBackend } from '../../../jwa/jwe/enc/aescbc/aescbc-jsonwebencryption-content-encryption.backend';
import { OctetSequenceJsonWebKey } from '../../../jwa/jwk/oct/octet-sequence.jsonwebkey';
import { JsonWebEncryptionHeaderParameters } from '../../jsonwebencryption-header.parameters';
import { FlattenedJsonWebEncryptionToken } from './flattened-jsonwebencryption.token';
import { serialize } from './serialize';

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

const invalidHeaders: any[] = [
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

const invalidRecipientUnprotectedHeaders: any[] = [
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

const repeatedJoseHeaderParameters: Partial<JsonWebEncryptionHeaderParameters>[][] = [
  [{ alg: 'A128KW' }, { alg: 'A128KW' }, { enc: 'A128CBC-HS256' }],
  [{ alg: 'A128KW' }, { enc: 'A128CBC-HS256' }, { alg: 'A128KW' }],
  [{ enc: 'A128CBC-HS256' }, { alg: 'A128KW' }, { alg: 'A128KW' }],
  [{ alg: 'A128KW' }, { alg: 'A128KW' }, { alg: 'A128KW' }],
];

const invalidSerializeOptions: any[] = [null, true, 1, 1.2, 1n, 'a', Symbol('a'), Buffer, Buffer.alloc(1), () => 1, []];

const invalidAads: any[] = [
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
];

const invalidDetacheds: any[] = [
  undefined,
  null,
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

describe('serialize()', () => {
  // #region Uncompressed Attached Token without Additional Authenticated Data
  const uncompressedProtectedAttachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    protected:
      'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyJ9',
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyJ9',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    ciphertext: 'KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY',
    tag: 'pf7CC-iGb8R2ZstoWHErWw',
  };

  const uncompressedUnprotectedAttachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    unprotected: { alg: 'A128KW', enc: 'A128CBC-HS256', jku: 'https://server.example.com/keys.jwks', kid: '7' },
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    ciphertext: 'KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY',
    tag: 'wOere2l7R7PoakOvvvxFCg',
  };

  const uncompressedRecipientAttachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    header: { alg: 'A128KW', enc: 'A128CBC-HS256', jku: 'https://server.example.com/keys.jwks', kid: '7' },
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    ciphertext: 'KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY',
    tag: 'wOere2l7R7PoakOvvvxFCg',
  };

  const uncompressedProtectedAndUnprotectedAttachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    protected: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    unprotected: { alg: 'A128KW', jku: 'https://server.example.com/keys.jwks', kid: '7' },
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    ciphertext: 'KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY',
    tag: 'Mz-VPPyU4RlcuYv1IwIvzw',
  };

  const uncompressedProtectedAndRecipientAttachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    protected: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    header: { alg: 'A128KW', jku: 'https://server.example.com/keys.jwks', kid: '7' },
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    ciphertext: 'KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY',
    tag: 'Mz-VPPyU4RlcuYv1IwIvzw',
  };

  const uncompressedUnprotectedAndRecipientAttachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    unprotected: { enc: 'A128CBC-HS256' },
    header: { alg: 'A128KW', jku: 'https://server.example.com/keys.jwks', kid: '7' },
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    ciphertext: 'KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY',
    tag: 'wOere2l7R7PoakOvvvxFCg',
  };

  const uncompressedFullAttachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    protected: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    unprotected: { jku: 'https://server.example.com/keys.jwks' },
    header: { alg: 'A128KW', kid: '7' },
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    ciphertext: 'KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY',
    tag: 'Mz-VPPyU4RlcuYv1IwIvzw',
  };
  // #endregion
  // #region Uncompressed Detached Token without Additional Authenticated Data
  const uncompressedProtectedDetachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    protected:
      'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyJ9',
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyJ9',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    tag: 'pf7CC-iGb8R2ZstoWHErWw',
  };

  const uncompressedUnprotectedDetachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    unprotected: { alg: 'A128KW', enc: 'A128CBC-HS256', jku: 'https://server.example.com/keys.jwks', kid: '7' },
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    tag: 'wOere2l7R7PoakOvvvxFCg',
  };

  const uncompressedRecipientDetachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    header: { alg: 'A128KW', enc: 'A128CBC-HS256', jku: 'https://server.example.com/keys.jwks', kid: '7' },
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    tag: 'wOere2l7R7PoakOvvvxFCg',
  };

  const uncompressedProtectedAndUnprotectedDetachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    protected: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    unprotected: { alg: 'A128KW', jku: 'https://server.example.com/keys.jwks', kid: '7' },
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    tag: 'Mz-VPPyU4RlcuYv1IwIvzw',
  };

  const uncompressedProtectedAndRecipientDetachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    protected: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    header: { alg: 'A128KW', jku: 'https://server.example.com/keys.jwks', kid: '7' },
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    tag: 'Mz-VPPyU4RlcuYv1IwIvzw',
  };

  const uncompressedUnprotectedAndRecipientDetachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    unprotected: { enc: 'A128CBC-HS256' },
    header: { alg: 'A128KW', jku: 'https://server.example.com/keys.jwks', kid: '7' },
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    tag: 'wOere2l7R7PoakOvvvxFCg',
  };

  const uncompressedFullDetachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    protected: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    unprotected: { jku: 'https://server.example.com/keys.jwks' },
    header: { alg: 'A128KW', kid: '7' },
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    tag: 'Mz-VPPyU4RlcuYv1IwIvzw',
  };
  // #endregion
  // #region Compressed Attached Token without Additional Authenticated Data
  const compressedProtectedAttachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    protected:
      'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiemlwIjoiREVGIiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyJ9',
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiemlwIjoiREVGIiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyJ9',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    ciphertext: '7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA',
    tag: '8nmSbluZF1Ws1sABt49r6Q',
  };

  const compressedUnprotectedAttachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    unprotected: {
      alg: 'A128KW',
      enc: 'A128CBC-HS256',
      zip: 'DEF',
      jku: 'https://server.example.com/keys.jwks',
      kid: '7',
    },
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    ciphertext: '7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA',
    tag: '6mQsBNyxIUzsP37fC54ZjQ',
  };

  const compressedRecipientAttachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    header: {
      alg: 'A128KW',
      enc: 'A128CBC-HS256',
      zip: 'DEF',
      jku: 'https://server.example.com/keys.jwks',
      kid: '7',
    },
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    ciphertext: '7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA',
    tag: '6mQsBNyxIUzsP37fC54ZjQ',
  };

  const compressedProtectedAndUnprotectedAttachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    protected: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    unprotected: { alg: 'A128KW', zip: 'DEF', jku: 'https://server.example.com/keys.jwks', kid: '7' },
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    ciphertext: '7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA',
    tag: 'FVFsNAUL3jgdAmZnSVxAFQ',
  };

  const compressedProtectedAndRecipientAttachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    protected: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    header: { alg: 'A128KW', zip: 'DEF', jku: 'https://server.example.com/keys.jwks', kid: '7' },
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    ciphertext: '7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA',
    tag: 'FVFsNAUL3jgdAmZnSVxAFQ',
  };

  const compressedUnprotectedAndRecipientAttachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    unprotected: { enc: 'A128CBC-HS256' },
    header: { alg: 'A128KW', zip: 'DEF', jku: 'https://server.example.com/keys.jwks', kid: '7' },
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    ciphertext: '7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA',
    tag: '6mQsBNyxIUzsP37fC54ZjQ',
  };

  const compressedFullAttachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    protected: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    unprotected: { jku: 'https://server.example.com/keys.jwks' },
    header: { alg: 'A128KW', zip: 'DEF', kid: '7' },
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    ciphertext: '7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA',
    tag: 'FVFsNAUL3jgdAmZnSVxAFQ',
  };
  // #endregion
  // #region Compressed Detached Token without Additional Authenticated Data
  const compressedProtectedDetachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    protected:
      'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiemlwIjoiREVGIiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyJ9',
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiemlwIjoiREVGIiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyJ9',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    tag: '8nmSbluZF1Ws1sABt49r6Q',
  };

  const compressedUnprotectedDetachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    unprotected: {
      alg: 'A128KW',
      enc: 'A128CBC-HS256',
      zip: 'DEF',
      jku: 'https://server.example.com/keys.jwks',
      kid: '7',
    },
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    tag: '6mQsBNyxIUzsP37fC54ZjQ',
  };

  const compressedRecipientDetachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    header: {
      alg: 'A128KW',
      enc: 'A128CBC-HS256',
      zip: 'DEF',
      jku: 'https://server.example.com/keys.jwks',
      kid: '7',
    },
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    tag: '6mQsBNyxIUzsP37fC54ZjQ',
  };

  const compressedProtectedAndUnprotectedDetachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    protected: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    unprotected: { alg: 'A128KW', zip: 'DEF', jku: 'https://server.example.com/keys.jwks', kid: '7' },
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    tag: 'FVFsNAUL3jgdAmZnSVxAFQ',
  };

  const compressedProtectedAndRecipientDetachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    protected: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    header: { alg: 'A128KW', zip: 'DEF', jku: 'https://server.example.com/keys.jwks', kid: '7' },
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    tag: 'FVFsNAUL3jgdAmZnSVxAFQ',
  };

  const compressedUnprotectedAndRecipientDetachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    unprotected: { enc: 'A128CBC-HS256' },
    header: { alg: 'A128KW', zip: 'DEF', jku: 'https://server.example.com/keys.jwks', kid: '7' },
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    tag: '6mQsBNyxIUzsP37fC54ZjQ',
  };

  const compressedFullDetachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    protected: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    unprotected: { jku: 'https://server.example.com/keys.jwks' },
    header: { alg: 'A128KW', zip: 'DEF', kid: '7' },
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    tag: 'FVFsNAUL3jgdAmZnSVxAFQ',
  };
  // #endregion
  // #region Uncompressed Attached Token with Additional Authenticated Data
  const uncompressedProtectedAttachedToken: FlattenedJsonWebEncryptionToken = {
    protected:
      'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyJ9',
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyJ9.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    ciphertext: 'KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY',
    tag: '2WcnJIVXlq2EYEbHWKr-7g',
  };

  const uncompressedUnprotectedAttachedToken: FlattenedJsonWebEncryptionToken = {
    unprotected: { alg: 'A128KW', enc: 'A128CBC-HS256', jku: 'https://server.example.com/keys.jwks', kid: '7' },
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: '.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    ciphertext: 'KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY',
    tag: 'W77Q108vf3uFnX_LmZPIlA',
  };

  const uncompressedRecipientAttachedToken: FlattenedJsonWebEncryptionToken = {
    header: { alg: 'A128KW', enc: 'A128CBC-HS256', jku: 'https://server.example.com/keys.jwks', kid: '7' },
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: '.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    ciphertext: 'KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY',
    tag: 'W77Q108vf3uFnX_LmZPIlA',
  };

  const uncompressedProtectedAndUnprotectedAttachedToken: FlattenedJsonWebEncryptionToken = {
    protected: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    unprotected: { alg: 'A128KW', jku: 'https://server.example.com/keys.jwks', kid: '7' },
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    ciphertext: 'KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY',
    tag: 'ULYMNP5lrIthBrdvAIzyqg',
  };

  const uncompressedProtectedAndRecipientAttachedToken: FlattenedJsonWebEncryptionToken = {
    protected: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    header: { alg: 'A128KW', jku: 'https://server.example.com/keys.jwks', kid: '7' },
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    ciphertext: 'KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY',
    tag: 'ULYMNP5lrIthBrdvAIzyqg',
  };

  const uncompressedUnprotectedAndRecipientAttachedToken: FlattenedJsonWebEncryptionToken = {
    unprotected: { enc: 'A128CBC-HS256' },
    header: { alg: 'A128KW', jku: 'https://server.example.com/keys.jwks', kid: '7' },
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: '.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    ciphertext: 'KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY',
    tag: 'W77Q108vf3uFnX_LmZPIlA',
  };

  const uncompressedFullAttachedToken: FlattenedJsonWebEncryptionToken = {
    protected: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    unprotected: { jku: 'https://server.example.com/keys.jwks' },
    header: { alg: 'A128KW', kid: '7' },
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    ciphertext: 'KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY',
    tag: 'ULYMNP5lrIthBrdvAIzyqg',
  };
  // #endregion
  // #region Uncompressed Detached Token with Additional Authenticated Data
  const uncompressedProtectedDetachedToken: FlattenedJsonWebEncryptionToken = {
    protected:
      'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyJ9',
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad:
      'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyJ9.' +
      'YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    tag: '2WcnJIVXlq2EYEbHWKr-7g',
  };

  const uncompressedUnprotectedDetachedToken: FlattenedJsonWebEncryptionToken = {
    unprotected: { alg: 'A128KW', enc: 'A128CBC-HS256', jku: 'https://server.example.com/keys.jwks', kid: '7' },
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: '.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    tag: 'W77Q108vf3uFnX_LmZPIlA',
  };

  const uncompressedRecipientDetachedToken: FlattenedJsonWebEncryptionToken = {
    header: { alg: 'A128KW', enc: 'A128CBC-HS256', jku: 'https://server.example.com/keys.jwks', kid: '7' },
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: '.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    tag: 'W77Q108vf3uFnX_LmZPIlA',
  };

  const uncompressedProtectedAndUnprotectedDetachedToken: FlattenedJsonWebEncryptionToken = {
    protected: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    unprotected: { alg: 'A128KW', jku: 'https://server.example.com/keys.jwks', kid: '7' },
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    tag: 'ULYMNP5lrIthBrdvAIzyqg',
  };

  const uncompressedProtectedAndRecipientDetachedToken: FlattenedJsonWebEncryptionToken = {
    protected: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    header: { alg: 'A128KW', jku: 'https://server.example.com/keys.jwks', kid: '7' },
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    tag: 'ULYMNP5lrIthBrdvAIzyqg',
  };

  const uncompressedUnprotectedAndRecipientDetachedToken: FlattenedJsonWebEncryptionToken = {
    unprotected: { enc: 'A128CBC-HS256' },
    header: { alg: 'A128KW', jku: 'https://server.example.com/keys.jwks', kid: '7' },
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: '.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    tag: 'W77Q108vf3uFnX_LmZPIlA',
  };

  const uncompressedFullDetachedToken: FlattenedJsonWebEncryptionToken = {
    protected: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    unprotected: { jku: 'https://server.example.com/keys.jwks' },
    header: { alg: 'A128KW', kid: '7' },
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    tag: 'ULYMNP5lrIthBrdvAIzyqg',
  };
  // #endregion
  // #region Compressed Attached Token with Additional Authenticated Data
  const compressedProtectedAttachedToken: FlattenedJsonWebEncryptionToken = {
    protected:
      'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiemlwIjoiREVGIiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyJ9',
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad:
      'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiemlwIjoiREVGIiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyJ9.' +
      'YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    ciphertext: '7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA',
    tag: 'SRoHlcdRqnsVScLWNZIwtA',
  };

  const compressedUnprotectedAttachedToken: FlattenedJsonWebEncryptionToken = {
    unprotected: {
      alg: 'A128KW',
      enc: 'A128CBC-HS256',
      zip: 'DEF',
      jku: 'https://server.example.com/keys.jwks',
      kid: '7',
    },
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: '.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    ciphertext: '7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA',
    tag: '0Z9lyKxM6Rz-6zCUcfNOmQ',
  };

  const compressedRecipientAttachedToken: FlattenedJsonWebEncryptionToken = {
    header: {
      alg: 'A128KW',
      enc: 'A128CBC-HS256',
      zip: 'DEF',
      jku: 'https://server.example.com/keys.jwks',
      kid: '7',
    },
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: '.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    ciphertext: '7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA',
    tag: '0Z9lyKxM6Rz-6zCUcfNOmQ',
  };

  const compressedProtectedAndUnprotectedAttachedToken: FlattenedJsonWebEncryptionToken = {
    protected: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    unprotected: { alg: 'A128KW', zip: 'DEF', jku: 'https://server.example.com/keys.jwks', kid: '7' },
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    ciphertext: '7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA',
    tag: '1IIFfjlJQ4EkqwKhBdlY5w',
  };

  const compressedProtectedAndRecipientAttachedToken: FlattenedJsonWebEncryptionToken = {
    protected: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    header: { alg: 'A128KW', zip: 'DEF', jku: 'https://server.example.com/keys.jwks', kid: '7' },
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    ciphertext: '7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA',
    tag: '1IIFfjlJQ4EkqwKhBdlY5w',
  };

  const compressedUnprotectedAndRecipientAttachedToken: FlattenedJsonWebEncryptionToken = {
    unprotected: { enc: 'A128CBC-HS256' },
    header: { alg: 'A128KW', zip: 'DEF', jku: 'https://server.example.com/keys.jwks', kid: '7' },
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: '.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    ciphertext: '7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA',
    tag: '0Z9lyKxM6Rz-6zCUcfNOmQ',
  };

  const compressedFullAttachedToken: FlattenedJsonWebEncryptionToken = {
    protected: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    unprotected: { jku: 'https://server.example.com/keys.jwks' },
    header: { alg: 'A128KW', zip: 'DEF', kid: '7' },
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    ciphertext: '7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA',
    tag: '1IIFfjlJQ4EkqwKhBdlY5w',
  };
  // #endregion
  // #region Compressed Detached Token with Additional Authenticated Data
  const compressedProtectedDetachedToken: FlattenedJsonWebEncryptionToken = {
    protected:
      'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiemlwIjoiREVGIiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyJ9',
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad:
      'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiemlwIjoiREVGIiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyJ9.' +
      'YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    tag: 'SRoHlcdRqnsVScLWNZIwtA',
  };

  const compressedUnprotectedDetachedToken: FlattenedJsonWebEncryptionToken = {
    unprotected: {
      alg: 'A128KW',
      enc: 'A128CBC-HS256',
      zip: 'DEF',
      jku: 'https://server.example.com/keys.jwks',
      kid: '7',
    },
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: '.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    tag: '0Z9lyKxM6Rz-6zCUcfNOmQ',
  };

  const compressedRecipientDetachedToken: FlattenedJsonWebEncryptionToken = {
    header: {
      alg: 'A128KW',
      enc: 'A128CBC-HS256',
      zip: 'DEF',
      jku: 'https://server.example.com/keys.jwks',
      kid: '7',
    },
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: '.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    tag: '0Z9lyKxM6Rz-6zCUcfNOmQ',
  };

  const compressedProtectedAndUnprotectedDetachedToken: FlattenedJsonWebEncryptionToken = {
    protected: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    unprotected: { alg: 'A128KW', zip: 'DEF', jku: 'https://server.example.com/keys.jwks', kid: '7' },
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    tag: '1IIFfjlJQ4EkqwKhBdlY5w',
  };

  const compressedProtectedAndRecipientDetachedToken: FlattenedJsonWebEncryptionToken = {
    protected: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    header: { alg: 'A128KW', zip: 'DEF', jku: 'https://server.example.com/keys.jwks', kid: '7' },
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    tag: '1IIFfjlJQ4EkqwKhBdlY5w',
  };

  const compressedUnprotectedAndRecipientDetachedToken: FlattenedJsonWebEncryptionToken = {
    unprotected: { enc: 'A128CBC-HS256' },
    header: { alg: 'A128KW', zip: 'DEF', jku: 'https://server.example.com/keys.jwks', kid: '7' },
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: '.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    tag: '0Z9lyKxM6Rz-6zCUcfNOmQ',
  };

  const compressedFullDetachedToken: FlattenedJsonWebEncryptionToken = {
    protected: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    unprotected: { jku: 'https://server.example.com/keys.jwks' },
    header: { alg: 'A128KW', zip: 'DEF', kid: '7' },
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    tag: '1IIFfjlJQ4EkqwKhBdlY5w',
  };
  // #endregion

  const plaintext = Buffer.from('Live long and prosper.');

  const encHeader: Partial<JsonWebEncryptionHeaderParameters> = { enc: 'A128CBC-HS256' };
  const jkuHeader: Partial<JsonWebEncryptionHeaderParameters> = { jku: 'https://server.example.com/keys.jwks' };
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

  const contentEncryptionKey = Buffer.from('BNMfxVSd_P4LZJ36P6pqzmt81C1vawnbyLEA8I-cLM8', 'base64url');
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
      .spyOn(AESKWJsonWebEncryptionKeyManagementBackend.prototype, 'generateContentEncryptionKey')
      .mockResolvedValueOnce(contentEncryptionKey);

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
        recipientUnprotectedHeader: algKidHeader,
      }),
    ).rejects.toThrowWithMessage(TypeError, 'The provided Plaintext is invalid.');
  });

  it.each(invalidHeaders)('should throw when the provided JSON Web Encryption Headers is invalid.', async (headers) => {
    await expect(serialize(plaintext, headers)).rejects.toThrowWithMessage(
      TypeError,
      'The provided JSON Web Encryption Headers is invalid.',
    );
  });

  it.each(invalidProtectedHeaders)(
    'should throw when the provided JSON Web Encryption Protected Header is invalid.',
    async (protectedHeader) => {
      await expect(
        serialize(plaintext, {
          protectedHeader,
          unprotectedHeader: jkuHeader,
          recipientUnprotectedHeader: algKidHeader,
        }),
      ).rejects.toThrowWithMessage(TypeError, 'The provided JSON Web Encryption Protected Header is invalid.');
    },
  );

  it.each(invalidUnprotectedHeaders)(
    'should throw when the provided JSON Web Encryption Unprotected Header is invalid.',
    async (unprotectedHeader) => {
      await expect(
        serialize(plaintext, {
          protectedHeader: encHeader,
          unprotectedHeader,
          recipientUnprotectedHeader: algKidHeader,
        }),
      ).rejects.toThrowWithMessage(TypeError, 'The provided JSON Web Encryption Unprotected Header is invalid.');
    },
  );

  it.each(invalidRecipientUnprotectedHeaders)(
    'should throw when the provided JSON Web Encryption Recipient Unprotected Header is invalid.',
    async (recipientUnprotectedHeader) => {
      await expect(
        serialize(plaintext, { protectedHeader: encHeader, unprotectedHeader: jkuHeader, recipientUnprotectedHeader }),
      ).rejects.toThrowWithMessage(
        TypeError,
        'The provided JSON Web Encryption Recipient Unprotected Header is invalid.',
      );
    },
  );

  it('should throw when no JSON Web Encryption Header is provided.', async () => {
    await expect(serialize(plaintext, {})).rejects.toThrowWithMessage(
      InvalidJoseHeaderError,
      'Missing at least one required JSON Web Encryption Header.',
    );
  });

  it.each(repeatedJoseHeaderParameters)(
    'should throw when there are repeated JSON Web Encryption Header Parameters.',
    async (protectedHeader, unprotectedHeader, recipientUnprotectedHeader) => {
      await expect(
        serialize(plaintext, { protectedHeader, unprotectedHeader, recipientUnprotectedHeader }),
      ).rejects.toThrowWithMessage(
        InvalidJoseHeaderError,
        'Cannot have repeated JSON Web Encryption Header Parameters.',
      );
    },
  );

  it.each(invalidSerializeOptions)('should throw when the provided options is invalid.', async (options) => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: encHeader, unprotectedHeader: jkuHeader, recipientUnprotectedHeader: algKidHeader },
        options,
      ),
    ).rejects.toThrowWithMessage(TypeError, 'The provided options is invalid.');
  });

  it.each(invalidAads)('should throw when the provided option "aad" is invalid.', async (aad) => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: encHeader, unprotectedHeader: jkuHeader, recipientUnprotectedHeader: algKidHeader },
        { aad },
      ),
    ).rejects.toThrowWithMessage(TypeError, 'The provided option "aad" is invalid.');
  });

  it.each(invalidJwks)('should throw when the provided option "jwk" is invalid.', async (jwk) => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: encHeader, unprotectedHeader: jkuHeader, recipientUnprotectedHeader: algKidHeader },
        { jwk },
      ),
    ).rejects.toThrowWithMessage(TypeError, 'The provided option "jwk" is invalid.');
  });

  it.each(invalidDetacheds)('should throw when the provided option "detached" is invalid.', async (detached) => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: encHeader, unprotectedHeader: jkuHeader, recipientUnprotectedHeader: algKidHeader },
        { detached },
      ),
    ).rejects.toThrowWithMessage(TypeError, 'The provided option "detached" is invalid.');
  });

  it('should throw when failing to serialize the provided Flattened JSON Web Encryption.', async () => {
    await expect(
      serialize(plaintext, { protectedHeader: encHeader, recipientUnprotectedHeader: algKidHeader }),
    ).rejects.toThrow();
  });

  it('should serialize a Flattened JSON Web Encryption Uncompressed Protected Attached Token with no Additional Authenticated Data.', async () => {
    await expect(serialize(plaintext, { protectedHeader: algEncJkuKidHeader }, { jwk })).resolves.toStrictEqual(
      uncompressedProtectedAttachedTokenNoAad,
    );
  });

  it('should serialize a Flattened JSON Web Encryption Uncompressed Unprotected Attached Token with no Additional Authenticated Data.', async () => {
    await expect(serialize(plaintext, { unprotectedHeader: algEncJkuKidHeader }, { jwk })).resolves.toStrictEqual(
      uncompressedUnprotectedAttachedTokenNoAad,
    );
  });

  it('should serialize a Flattened JSON Web Encryption Uncompressed Recipient Unprotected Attached Token with no Additional Authenticated Data.', async () => {
    await expect(
      serialize(plaintext, { recipientUnprotectedHeader: algEncJkuKidHeader }, { jwk }),
    ).resolves.toStrictEqual(uncompressedRecipientAttachedTokenNoAad);
  });

  it('should serialize a Flattened JSON Web Encryption Uncompressed Protected and Unprotected Attached Token with no Additional Authenticated Data.', async () => {
    await expect(
      serialize(plaintext, { protectedHeader: encHeader, unprotectedHeader: algJkuKidHeader }, { jwk }),
    ).resolves.toStrictEqual(uncompressedProtectedAndUnprotectedAttachedTokenNoAad);
  });

  it('should serialize a Flattened JSON Web Encryption Uncompressed Protected and Recipient Unprotected Attached Token with no Additional Authenticated Data.', async () => {
    await expect(
      serialize(plaintext, { protectedHeader: encHeader, recipientUnprotectedHeader: algJkuKidHeader }, { jwk }),
    ).resolves.toStrictEqual(uncompressedProtectedAndRecipientAttachedTokenNoAad);
  });

  it('should serialize a Flattened JSON Web Encryption Uncompressed Unprotected and Recipient Unprotected Attached Token with no Additional Authenticated Data.', async () => {
    await expect(
      serialize(plaintext, { unprotectedHeader: encHeader, recipientUnprotectedHeader: algJkuKidHeader }, { jwk }),
    ).resolves.toStrictEqual(uncompressedUnprotectedAndRecipientAttachedTokenNoAad);
  });

  it('should serialize a Flattened JSON Web Encryption Uncompressed Full Attached Token with no Additional Authenticated Data.', async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: encHeader, unprotectedHeader: jkuHeader, recipientUnprotectedHeader: algKidHeader },
        { jwk },
      ),
    ).resolves.toStrictEqual(uncompressedFullAttachedTokenNoAad);
  });

  it('should serialize a Flattened JSON Web Encryption Uncompressed Protected Detached Token with no Additional Authenticated Data.', async () => {
    await expect(
      serialize(plaintext, { protectedHeader: algEncJkuKidHeader }, { jwk, detached: true }),
    ).resolves.toStrictEqual(uncompressedProtectedDetachedTokenNoAad);
  });

  it('should serialize a Flattened JSON Web Encryption Uncompressed Unprotected Detached Token with no Additional Authenticated Data.', async () => {
    await expect(
      serialize(plaintext, { unprotectedHeader: algEncJkuKidHeader }, { jwk, detached: true }),
    ).resolves.toStrictEqual(uncompressedUnprotectedDetachedTokenNoAad);
  });

  it('should serialize a Flattened JSON Web Encryption Uncompressed Recipient Unprotected Detached Token with no Additional Authenticated Data.', async () => {
    await expect(
      serialize(plaintext, { recipientUnprotectedHeader: algEncJkuKidHeader }, { jwk, detached: true }),
    ).resolves.toStrictEqual(uncompressedRecipientDetachedTokenNoAad);
  });

  it('should serialize a Flattened JSON Web Encryption Uncompressed Protected and Unprotected Detached Token with no Additional Authenticated Data.', async () => {
    await expect(
      serialize(plaintext, { protectedHeader: encHeader, unprotectedHeader: algJkuKidHeader }, { jwk, detached: true }),
    ).resolves.toStrictEqual(uncompressedProtectedAndUnprotectedDetachedTokenNoAad);
  });

  it('should serialize a Flattened JSON Web Encryption Uncompressed Protected and Recipient Unprotected Detached Token with no Additional Authenticated Data.', async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: encHeader, recipientUnprotectedHeader: algJkuKidHeader },
        { jwk, detached: true },
      ),
    ).resolves.toStrictEqual(uncompressedProtectedAndRecipientDetachedTokenNoAad);
  });

  it('should serialize a Flattened JSON Web Encryption Uncompressed Unprotected and Recipient Unprotected Detached Token with no Additional Authenticated Data.', async () => {
    await expect(
      serialize(
        plaintext,
        { unprotectedHeader: encHeader, recipientUnprotectedHeader: algJkuKidHeader },
        { jwk, detached: true },
      ),
    ).resolves.toStrictEqual(uncompressedUnprotectedAndRecipientDetachedTokenNoAad);
  });

  it('should serialize a Flattened JSON Web Encryption Uncompressed Full Detached Token with no Additional Authenticated Data.', async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: encHeader, unprotectedHeader: jkuHeader, recipientUnprotectedHeader: algKidHeader },
        { jwk, detached: true },
      ),
    ).resolves.toStrictEqual(uncompressedFullDetachedTokenNoAad);
  });

  it('should serialize a Flattened JSON Web Encryption Compressed Protected Attached Token with no Additional Authenticated Data.', async () => {
    await expect(serialize(plaintext, { protectedHeader: algEncZipJkuKidHeader }, { jwk })).resolves.toStrictEqual(
      compressedProtectedAttachedTokenNoAad,
    );
  });

  it('should serialize a Flattened JSON Web Encryption Compressed Unprotected Attached Token with no Additional Authenticated Data.', async () => {
    await expect(serialize(plaintext, { unprotectedHeader: algEncZipJkuKidHeader }, { jwk })).resolves.toStrictEqual(
      compressedUnprotectedAttachedTokenNoAad,
    );
  });

  it('should serialize a Flattened JSON Web Encryption Compressed Recipient Unprotected Attached Token with no Additional Authenticated Data.', async () => {
    await expect(
      serialize(plaintext, { recipientUnprotectedHeader: algEncZipJkuKidHeader }, { jwk }),
    ).resolves.toStrictEqual(compressedRecipientAttachedTokenNoAad);
  });

  it('should serialize a Flattened JSON Web Encryption Compressed Protected and Unprotected Attached Token with no Additional Authenticated Data.', async () => {
    await expect(
      serialize(plaintext, { protectedHeader: encHeader, unprotectedHeader: algZipJkuKidHeader }, { jwk }),
    ).resolves.toStrictEqual(compressedProtectedAndUnprotectedAttachedTokenNoAad);
  });

  it('should serialize a Flattened JSON Web Encryption Compressed Protected and Recipient Unprotected Attached Token with no Additional Authenticated Data.', async () => {
    await expect(
      serialize(plaintext, { protectedHeader: encHeader, recipientUnprotectedHeader: algZipJkuKidHeader }, { jwk }),
    ).resolves.toStrictEqual(compressedProtectedAndRecipientAttachedTokenNoAad);
  });

  it('should serialize a Flattened JSON Web Encryption Compressed Unprotected and Recipient Unprotected Attached Token with no Additional Authenticated Data.', async () => {
    await expect(
      serialize(plaintext, { unprotectedHeader: encHeader, recipientUnprotectedHeader: algZipJkuKidHeader }, { jwk }),
    ).resolves.toStrictEqual(compressedUnprotectedAndRecipientAttachedTokenNoAad);
  });

  it('should serialize a Flattened JSON Web Encryption Compressed Full Attached Token with no Additional Authenticated Data.', async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: encHeader, unprotectedHeader: jkuHeader, recipientUnprotectedHeader: algZipKidHeader },
        { jwk },
      ),
    ).resolves.toStrictEqual(compressedFullAttachedTokenNoAad);
  });

  it('should serialize a Flattened JSON Web Encryption Compressed Protected Detached Token with no Additional Authenticated Data.', async () => {
    await expect(
      serialize(plaintext, { protectedHeader: algEncZipJkuKidHeader }, { jwk, detached: true }),
    ).resolves.toStrictEqual(compressedProtectedDetachedTokenNoAad);
  });

  it('should serialize a Flattened JSON Web Encryption Compressed Unprotected Detached Token with no Additional Authenticated Data.', async () => {
    await expect(
      serialize(plaintext, { unprotectedHeader: algEncZipJkuKidHeader }, { jwk, detached: true }),
    ).resolves.toStrictEqual(compressedUnprotectedDetachedTokenNoAad);
  });

  it('should serialize a Flattened JSON Web Encryption Compressed Recipient Unprotected Detached Token with no Additional Authenticated Data.', async () => {
    await expect(
      serialize(plaintext, { recipientUnprotectedHeader: algEncZipJkuKidHeader }, { jwk, detached: true }),
    ).resolves.toStrictEqual(compressedRecipientDetachedTokenNoAad);
  });

  it('should serialize a Flattened JSON Web Encryption Compressed Protected and Unprotected Detached Token with no Additional Authenticated Data.', async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: encHeader, unprotectedHeader: algZipJkuKidHeader },
        { jwk, detached: true },
      ),
    ).resolves.toStrictEqual(compressedProtectedAndUnprotectedDetachedTokenNoAad);
  });

  it('should serialize a Flattened JSON Web Encryption Compressed Protected and Recipient Unprotected Detached Token with no Additional Authenticated Data.', async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: encHeader, recipientUnprotectedHeader: algZipJkuKidHeader },
        { jwk, detached: true },
      ),
    ).resolves.toStrictEqual(compressedProtectedAndRecipientDetachedTokenNoAad);
  });

  it('should serialize a Flattened JSON Web Encryption Compressed Unprotected and Recipient Unprotected Detached Token with no Additional Authenticated Data.', async () => {
    await expect(
      serialize(
        plaintext,
        { unprotectedHeader: encHeader, recipientUnprotectedHeader: algZipJkuKidHeader },
        { jwk, detached: true },
      ),
    ).resolves.toStrictEqual(compressedUnprotectedAndRecipientDetachedTokenNoAad);
  });

  it('should serialize a Flattened JSON Web Encryption Compressed Full Detached Token with no Additional Authenticated Data.', async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: encHeader, unprotectedHeader: jkuHeader, recipientUnprotectedHeader: algZipKidHeader },
        { jwk, detached: true },
      ),
    ).resolves.toStrictEqual(compressedFullDetachedTokenNoAad);
  });

  it('should serialize a Flattened JSON Web Encryption Uncompressed Protected Attached Token with Additional Authenticated Data.', async () => {
    await expect(
      serialize(plaintext, { protectedHeader: algEncJkuKidHeader }, { aad: additionalAuthenticatedData, jwk }),
    ).resolves.toStrictEqual(uncompressedProtectedAttachedToken);
  });

  it('should serialize a Flattened JSON Web Encryption Uncompressed Unprotected Attached Token with Additional Authenticated Data.', async () => {
    await expect(
      serialize(plaintext, { unprotectedHeader: algEncJkuKidHeader }, { aad: additionalAuthenticatedData, jwk }),
    ).resolves.toStrictEqual(uncompressedUnprotectedAttachedToken);
  });

  it('should serialize a Flattened JSON Web Encryption Uncompressed Recipient Unprotected Attached Token with Additional Authenticated Data.', async () => {
    await expect(
      serialize(
        plaintext,
        { recipientUnprotectedHeader: algEncJkuKidHeader },
        { aad: additionalAuthenticatedData, jwk },
      ),
    ).resolves.toStrictEqual(uncompressedRecipientAttachedToken);
  });

  it('should serialize a Flattened JSON Web Encryption Uncompressed Protected and Unprotected Attached Token with Additional Authenticated Data.', async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: encHeader, unprotectedHeader: algJkuKidHeader },
        { aad: additionalAuthenticatedData, jwk },
      ),
    ).resolves.toStrictEqual(uncompressedProtectedAndUnprotectedAttachedToken);
  });

  it('should serialize a Flattened JSON Web Encryption Uncompressed Protected and Recipient Unprotected Attached Token with Additional Authenticated Data.', async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: encHeader, recipientUnprotectedHeader: algJkuKidHeader },
        { aad: additionalAuthenticatedData, jwk },
      ),
    ).resolves.toStrictEqual(uncompressedProtectedAndRecipientAttachedToken);
  });

  it('should serialize a Flattened JSON Web Encryption Uncompressed Unprotected and Recipient Unprotected Attached Token with Additional Authenticated Data.', async () => {
    await expect(
      serialize(
        plaintext,
        { unprotectedHeader: encHeader, recipientUnprotectedHeader: algJkuKidHeader },
        { aad: additionalAuthenticatedData, jwk },
      ),
    ).resolves.toStrictEqual(uncompressedUnprotectedAndRecipientAttachedToken);
  });

  it('should serialize a Flattened JSON Web Encryption Uncompressed Full Attached Token with Additional Authenticated Data.', async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: encHeader, unprotectedHeader: jkuHeader, recipientUnprotectedHeader: algKidHeader },
        { aad: additionalAuthenticatedData, jwk },
      ),
    ).resolves.toStrictEqual(uncompressedFullAttachedToken);
  });

  it('should serialize a Flattened JSON Web Encryption Uncompressed Protected Detached Token with Additional Authenticated Data.', async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: algEncJkuKidHeader },
        { aad: additionalAuthenticatedData, jwk, detached: true },
      ),
    ).resolves.toStrictEqual(uncompressedProtectedDetachedToken);
  });

  it('should serialize a Flattened JSON Web Encryption Uncompressed Unprotected Detached Token with Additional Authenticated Data.', async () => {
    await expect(
      serialize(
        plaintext,
        { unprotectedHeader: algEncJkuKidHeader },
        { aad: additionalAuthenticatedData, jwk, detached: true },
      ),
    ).resolves.toStrictEqual(uncompressedUnprotectedDetachedToken);
  });

  it('should serialize a Flattened JSON Web Encryption Uncompressed Recipient Unprotected Detached Token with Additional Authenticated Data.', async () => {
    await expect(
      serialize(
        plaintext,
        { recipientUnprotectedHeader: algEncJkuKidHeader },
        { aad: additionalAuthenticatedData, jwk, detached: true },
      ),
    ).resolves.toStrictEqual(uncompressedRecipientDetachedToken);
  });

  it('should serialize a Flattened JSON Web Encryption Uncompressed Protected and Unprotected Detached Token with Additional Authenticated Data.', async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: encHeader, unprotectedHeader: algJkuKidHeader },
        { aad: additionalAuthenticatedData, jwk, detached: true },
      ),
    ).resolves.toStrictEqual(uncompressedProtectedAndUnprotectedDetachedToken);
  });

  it('should serialize a Flattened JSON Web Encryption Uncompressed Protected and Recipient Unprotected Detached Token with Additional Authenticated Data.', async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: encHeader, recipientUnprotectedHeader: algJkuKidHeader },
        { aad: additionalAuthenticatedData, jwk, detached: true },
      ),
    ).resolves.toStrictEqual(uncompressedProtectedAndRecipientDetachedToken);
  });

  it('should serialize a Flattened JSON Web Encryption Uncompressed Unprotected and Recipient Unprotected Detached Token with Additional Authenticated Data.', async () => {
    await expect(
      serialize(
        plaintext,
        { unprotectedHeader: encHeader, recipientUnprotectedHeader: algJkuKidHeader },
        { aad: additionalAuthenticatedData, jwk, detached: true },
      ),
    ).resolves.toStrictEqual(uncompressedUnprotectedAndRecipientDetachedToken);
  });

  it('should serialize a Flattened JSON Web Encryption Uncompressed Full Detached Token with Additional Authenticated Data.', async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: encHeader, unprotectedHeader: jkuHeader, recipientUnprotectedHeader: algKidHeader },
        { aad: additionalAuthenticatedData, jwk, detached: true },
      ),
    ).resolves.toStrictEqual(uncompressedFullDetachedToken);
  });

  it('should serialize a Flattened JSON Web Encryption Compressed Protected Attached Token with Additional Authenticated Data.', async () => {
    await expect(
      serialize(plaintext, { protectedHeader: algEncZipJkuKidHeader }, { aad: additionalAuthenticatedData, jwk }),
    ).resolves.toStrictEqual(compressedProtectedAttachedToken);
  });

  it('should serialize a Flattened JSON Web Encryption Compressed Unprotected Attached Token with Additional Authenticated Data.', async () => {
    await expect(
      serialize(plaintext, { unprotectedHeader: algEncZipJkuKidHeader }, { aad: additionalAuthenticatedData, jwk }),
    ).resolves.toStrictEqual(compressedUnprotectedAttachedToken);
  });

  it('should serialize a Flattened JSON Web Encryption Compressed Recipient Unprotected Attached Token with Additional Authenticated Data.', async () => {
    await expect(
      serialize(
        plaintext,
        { recipientUnprotectedHeader: algEncZipJkuKidHeader },
        { aad: additionalAuthenticatedData, jwk },
      ),
    ).resolves.toStrictEqual(compressedRecipientAttachedToken);
  });

  it('should serialize a Flattened JSON Web Encryption Compressed Protected and Unprotected Attached Token with Additional Authenticated Data.', async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: encHeader, unprotectedHeader: algZipJkuKidHeader },
        { aad: additionalAuthenticatedData, jwk },
      ),
    ).resolves.toStrictEqual(compressedProtectedAndUnprotectedAttachedToken);
  });

  it('should serialize a Flattened JSON Web Encryption Compressed Protected and Recipient Unprotected Attached Token with Additional Authenticated Data.', async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: encHeader, recipientUnprotectedHeader: algZipJkuKidHeader },
        { aad: additionalAuthenticatedData, jwk },
      ),
    ).resolves.toStrictEqual(compressedProtectedAndRecipientAttachedToken);
  });

  it('should serialize a Flattened JSON Web Encryption Compressed Unprotected and Recipient Unprotected Attached Token with Additional Authenticated Data.', async () => {
    await expect(
      serialize(
        plaintext,
        { unprotectedHeader: encHeader, recipientUnprotectedHeader: algZipJkuKidHeader },
        { aad: additionalAuthenticatedData, jwk },
      ),
    ).resolves.toStrictEqual(compressedUnprotectedAndRecipientAttachedToken);
  });

  it('should serialize a Flattened JSON Web Encryption Compressed Full Attached Token with Additional Authenticated Data.', async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: encHeader, unprotectedHeader: jkuHeader, recipientUnprotectedHeader: algZipKidHeader },
        { aad: additionalAuthenticatedData, jwk },
      ),
    ).resolves.toStrictEqual(compressedFullAttachedToken);
  });

  it('should serialize a Flattened JSON Web Encryption Compressed Protected Detached Token with Additional Authenticated Data.', async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: algEncZipJkuKidHeader },
        { aad: additionalAuthenticatedData, jwk, detached: true },
      ),
    ).resolves.toStrictEqual(compressedProtectedDetachedToken);
  });

  it('should serialize a Flattened JSON Web Encryption Compressed Unprotected Detached Token with Additional Authenticated Data.', async () => {
    await expect(
      serialize(
        plaintext,
        { unprotectedHeader: algEncZipJkuKidHeader },
        { aad: additionalAuthenticatedData, jwk, detached: true },
      ),
    ).resolves.toStrictEqual(compressedUnprotectedDetachedToken);
  });

  it('should serialize a Flattened JSON Web Encryption Compressed Recipient Unprotected Detached Token with Additional Authenticated Data.', async () => {
    await expect(
      serialize(
        plaintext,
        { recipientUnprotectedHeader: algEncZipJkuKidHeader },
        { aad: additionalAuthenticatedData, jwk, detached: true },
      ),
    ).resolves.toStrictEqual(compressedRecipientDetachedToken);
  });

  it('should serialize a Flattened JSON Web Encryption Compressed Protected and Unprotected Detached Token with Additional Authenticated Data.', async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: encHeader, unprotectedHeader: algZipJkuKidHeader },
        { aad: additionalAuthenticatedData, jwk, detached: true },
      ),
    ).resolves.toStrictEqual(compressedProtectedAndUnprotectedDetachedToken);
  });

  it('should serialize a Flattened JSON Web Encryption Compressed Protected and Recipient Unprotected Detached Token with Additional Authenticated Data.', async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: encHeader, recipientUnprotectedHeader: algZipJkuKidHeader },
        { aad: additionalAuthenticatedData, jwk, detached: true },
      ),
    ).resolves.toStrictEqual(compressedProtectedAndRecipientDetachedToken);
  });

  it('should serialize a Flattened JSON Web Encryption Compressed Unprotected and Recipient Unprotected Detached Token with Additional Authenticated Data.', async () => {
    await expect(
      serialize(
        plaintext,
        { unprotectedHeader: encHeader, recipientUnprotectedHeader: algZipJkuKidHeader },
        { aad: additionalAuthenticatedData, jwk, detached: true },
      ),
    ).resolves.toStrictEqual(compressedUnprotectedAndRecipientDetachedToken);
  });

  it('should serialize a Flattened JSON Web Encryption Compressed Full Detached Token with Additional Authenticated Data.', async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: encHeader, unprotectedHeader: jkuHeader, recipientUnprotectedHeader: algZipKidHeader },
        { aad: additionalAuthenticatedData, jwk, detached: true },
      ),
    ).resolves.toStrictEqual(compressedFullDetachedToken);
  });
});
