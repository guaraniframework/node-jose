import { Buffer } from 'buffer';
import https from 'https';
import { Stream } from 'stream';

import { jsonStringify } from '@guarani/primitives';

import { InvalidJsonWebEncryptionError } from '../../../errors/invalid-jsonwebencryption.error';
import { OctetSequenceJsonWebKey } from '../../../jwa/jwk/oct/octet-sequence.jsonwebkey';
import { JsonWebEncryptionHeader } from '../../jsonwebencryption-header';
import { JsonWebEncryptionHeaderParameters } from '../../jsonwebencryption-header.parameters';
import { deserialize } from './deserialize';
import { FlattenedJsonWebEncryption } from './flattened-jsonwebencryption';
import { FlattenedJsonWebEncryptionToken } from './flattened-jsonwebencryption.token';

const invalidDeserializeOptions: any[] = [
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

const invalidExpectedAlgorithms: any[] = [
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
  ['a'],
];

const invalidDetachedCiphertexts: any[] = [
  null,
  true,
  1,
  1.2,
  1n,
  Symbol('a'),
  Buffer,
  () => 1,
  {},
  [],
  Buffer.alloc(0),
];

const invalidTokens: any[] = [undefined, null, true, 1, 1.2, 1n, '', Symbol('a'), Buffer, Buffer.alloc(1), () => 1, []];

describe('deserialize()', () => {
  const wrongEkToken: FlattenedJsonWebEncryptionToken = {
    protected: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    unprotected: { jku: 'https://server.example.com/keys.jwks' },
    header: { alg: 'A128KW', kid: '7' },
    encrypted_key: 'anBl9PSuJobKWwzWzJCqfMnejCvM5-WadN3zXMGyoCLW8_xmUldY3Q',
    aad: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    ciphertext: 'KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY',
    tag: 'U0m_YmjN04DJvceFICbCVQ',
  };

  const wrongAadToken: FlattenedJsonWebEncryptionToken = {
    protected: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    unprotected: { jku: 'https://server.example.com/keys.jwks' },
    header: { alg: 'A128KW', kid: '7' },
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: 'eyJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    ciphertext: 'KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY',
    tag: 'U0m_YmjN04DJvceFICbCVQ',
  };

  const wrongIvToken: FlattenedJsonWebEncryptionToken = {
    protected: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    unprotected: { jku: 'https://server.example.com/keys.jwks' },
    header: { alg: 'A128KW', kid: '7' },
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    iv: 'eE63cGwX4T7eSspUA72t2Q',
    ciphertext: 'KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY',
    tag: 'U0m_YmjN04DJvceFICbCVQ',
  };

  const wrongCiphertextToken: FlattenedJsonWebEncryptionToken = {
    protected: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    unprotected: { jku: 'https://server.example.com/keys.jwks' },
    header: { alg: 'A128KW', kid: '7' },
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    ciphertext: 'giYkZlt454236QV7AdREOuT0UOQrnNW1dpTna5JQpDk',
    tag: 'U0m_YmjN04DJvceFICbCVQ',
  };

  const wrongTagToken: FlattenedJsonWebEncryptionToken = {
    protected: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    unprotected: { jku: 'https://server.example.com/keys.jwks' },
    header: { alg: 'A128KW', kid: '7' },
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    ciphertext: 'KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY',
    tag: '24tpOFXtrTHSIdllxDRtlw',
  };

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

  const ciphertext = Buffer.from('KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY', 'base64url');
  const compressedCiphertext = Buffer.from('7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA', 'base64url');

  const jwk = new OctetSequenceJsonWebKey({ kty: 'oct', k: 'GawgguFyGrWKav7AX4VKUg', kid: '7' });

  beforeEach(() => {
    https.get = jest.fn().mockImplementation((_, cb) => {
      const stream = new Stream();
      cb(stream);
      stream.emit('data', jsonStringify({ keys: [jwk.parameters] }));
      stream.emit('end');
    });
  });

  it.each(invalidDeserializeOptions)('should throw when the provided options is invalid.', async (options) => {
    await expect(deserialize(uncompressedProtectedAttachedTokenNoAad, options)).rejects.toThrowWithMessage(
      TypeError,
      'The provided options is invalid.',
    );
  });

  it.each(invalidJwks)('should throw when the provided option "jwk" is invalid.', async (jwk) => {
    await expect(deserialize(uncompressedProtectedAttachedTokenNoAad, { jwk })).rejects.toThrowWithMessage(
      TypeError,
      'The provided option "jwk" is invalid.',
    );
  });

  it.each(invalidExpectedAlgorithms)(
    'should throw when the provided option "expectedKeyManagementAlgorithms" is invalid.',
    async (expectedKeyManagementAlgorithms) => {
      await expect(
        deserialize(uncompressedProtectedAttachedTokenNoAad, { expectedKeyManagementAlgorithms }),
      ).rejects.toThrowWithMessage(TypeError, 'The provided option "expectedKeyManagementAlgorithms" is invalid.');
    },
  );

  it.each(invalidExpectedAlgorithms)(
    'should throw when the provided option "expectedContentEncryptionAlgorithms" is invalid.',
    async (expectedContentEncryptionAlgorithms) => {
      await expect(
        deserialize(uncompressedProtectedAttachedTokenNoAad, { expectedContentEncryptionAlgorithms }),
      ).rejects.toThrowWithMessage(TypeError, 'The provided option "expectedContentEncryptionAlgorithms" is invalid.');
    },
  );

  it.each(invalidExpectedAlgorithms)(
    'should throw when the provided option "expectedCompressionAlgorithms" is invalid.',
    async (expectedCompressionAlgorithms) => {
      await expect(
        deserialize(uncompressedProtectedAttachedTokenNoAad, { expectedCompressionAlgorithms }),
      ).rejects.toThrowWithMessage(TypeError, 'The provided option "expectedCompressionAlgorithms" is invalid.');
    },
  );

  it.each(invalidDetachedCiphertexts)(
    'should throw when the provided option "detachedCiphertext" is invalid.',
    async (detachedCiphertext) => {
      await expect(
        deserialize(uncompressedProtectedAttachedTokenNoAad, { detachedCiphertext }),
      ).rejects.toThrowWithMessage(TypeError, 'The provided option "detachedCiphertext" is invalid.');
    },
  );

  it.each(invalidTokens)(
    'should throw when the provided Flattened JSON Web Encryption Token is invalid.',
    async (token) => {
      await expect(deserialize(token)).rejects.toThrowWithMessage(
        TypeError,
        'The provided Flattened JSON Web Encryption Token is invalid.',
      );
    },
  );

  it('should throw when deserializing a Detached Flattened JSON Web Encryption Token and not providing a Detached Ciphertext.', async () => {
    await expect(deserialize(uncompressedProtectedDetachedTokenNoAad)).rejects.toThrowWithMessage(
      InvalidJsonWebEncryptionError,
      'The JSON Web Encryption requires a valid Ciphertext.',
    );
  });

  it('should throw when providing a Detached Ciphertext for a Flattened JSON Web Encryption Token that already has a Ciphertext.', async () => {
    await expect(
      deserialize(uncompressedProtectedAttachedTokenNoAad, { detachedCiphertext: ciphertext }),
    ).rejects.toThrowWithMessage(
      InvalidJsonWebEncryptionError,
      'The provided JSON Web Encryption already has a defined Ciphertext.',
    );
  });

  it('should throw when the JSON Web Encryption Key Management Algorithm of the Flattened JSON Web Encryption Token is unexpected.', async () => {
    await expect(
      deserialize(uncompressedProtectedAttachedTokenNoAad, { expectedKeyManagementAlgorithms: ['A256KW'] }),
    ).rejects.toThrowWithMessage(
      InvalidJsonWebEncryptionError,
      'Unexpected JSON Web Encryption Key Management Algorithm "A128KW".',
    );
  });

  it('should throw when the JSON Web Encryption Content Encryption Algorithm of the Flattened JSON Web Encryption Token is unexpected.', async () => {
    await expect(
      deserialize(uncompressedProtectedAttachedTokenNoAad, { expectedContentEncryptionAlgorithms: ['A256CBC-HS512'] }),
    ).rejects.toThrowWithMessage(
      InvalidJsonWebEncryptionError,
      'Unexpected JSON Web Encryption Content Encryption Algorithm "A128CBC-HS256".',
    );
  });

  it('should throw when the JSON Web Encryption Compression Algorithm of the Flattened JSON Web Encryption Token is unexpected.', async () => {
    await expect(
      deserialize(uncompressedProtectedAttachedTokenNoAad, { expectedCompressionAlgorithms: ['DEF'] }),
    ).rejects.toThrowWithMessage(
      InvalidJsonWebEncryptionError,
      'Unexpected JSON Web Encryption Compression Algorithm "".',
    );
  });

  it('should throw when the provided Encrypted Key fails to deserialize the provided Flattened JSON Web Encryption Token.', async () => {
    await expect(deserialize(wrongEkToken, { jwk })).rejects.toThrow();
  });

  it('should throw when the provided Additional Authenticated Data fails to deserialize the provided Flattened JSON Web Encryption Token.', async () => {
    await expect(deserialize(wrongAadToken, { jwk })).rejects.toThrow();
  });

  it('should throw when the provided Initialization Vector fails to deserialize the provided Flattened JSON Web Encryption Token.', async () => {
    await expect(deserialize(wrongIvToken, { jwk })).rejects.toThrow();
  });

  it('should throw when the provided Ciphertext fails to deserialize the provided Flattened JSON Web Encryption Token.', async () => {
    await expect(deserialize(wrongCiphertextToken, { jwk })).rejects.toThrow();
  });

  it('should throw when the provided Authentication Tag fails to deserialize the provided Flattened JSON Web Encryption Token.', async () => {
    await expect(deserialize(wrongTagToken, { jwk })).rejects.toThrow();
  });

  it('should return the deserialized Flattened JSON Web Encryption from an Uncompressed Protected Attached Token with no Additional Authenticated Data.', async () => {
    let jwe!: FlattenedJsonWebEncryption;

    await expect(
      async () => (jwe = await deserialize(uncompressedProtectedAttachedTokenNoAad, { jwk })),
    ).resolves.not.toThrow();

    expect(jwe.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.header.parameters).toStrictEqual(algEncJkuKidHeader);

    expect(jwe.protectedHeader).toStrictEqual(algEncJkuKidHeader);
    expect(jwe.unprotectedHeader).toBeUndefined();
    expect(jwe.recipientUnprotectedHeader).toBeUndefined();

    expect(jwe.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from an Uncompressed Unprotected Attached Token with no Additional Authenticated Data.', async () => {
    let jwe!: FlattenedJsonWebEncryption;

    await expect(
      async () => (jwe = await deserialize(uncompressedUnprotectedAttachedTokenNoAad, { jwk })),
    ).resolves.not.toThrow();

    expect(jwe.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.header.parameters).toStrictEqual(algEncJkuKidHeader);

    expect(jwe.protectedHeader).toBeUndefined();
    expect(jwe.unprotectedHeader).toStrictEqual(algEncJkuKidHeader);
    expect(jwe.recipientUnprotectedHeader).toBeUndefined();

    expect(jwe.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from an Uncompressed Recipient Attached Token with no Additional Authenticated Data.', async () => {
    let jwe!: FlattenedJsonWebEncryption;

    await expect(
      async () => (jwe = await deserialize(uncompressedRecipientAttachedTokenNoAad, { jwk })),
    ).resolves.not.toThrow();

    expect(jwe.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.header.parameters).toStrictEqual(algEncJkuKidHeader);

    expect(jwe.protectedHeader).toBeUndefined();
    expect(jwe.unprotectedHeader).toBeUndefined();
    expect(jwe.recipientUnprotectedHeader).toStrictEqual(algEncJkuKidHeader);

    expect(jwe.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from an Uncompressed Protected and Unprotected Attached Token with no Additional Authenticated Data.', async () => {
    let jwe!: FlattenedJsonWebEncryption;

    await expect(
      async () => (jwe = await deserialize(uncompressedProtectedAndUnprotectedAttachedTokenNoAad, { jwk })),
    ).resolves.not.toThrow();

    expect(jwe.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.header.parameters).toStrictEqual(algEncJkuKidHeader);

    expect(jwe.protectedHeader).toStrictEqual(encHeader);
    expect(jwe.unprotectedHeader).toStrictEqual(algJkuKidHeader);
    expect(jwe.recipientUnprotectedHeader).toBeUndefined();

    expect(jwe.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from an Uncompressed Protected and Recipient Attached Token with no Additional Authenticated Data.', async () => {
    let jwe!: FlattenedJsonWebEncryption;

    await expect(
      async () => (jwe = await deserialize(uncompressedProtectedAndRecipientAttachedTokenNoAad, { jwk })),
    ).resolves.not.toThrow();

    expect(jwe.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.header.parameters).toStrictEqual(algEncJkuKidHeader);

    expect(jwe.protectedHeader).toStrictEqual(encHeader);
    expect(jwe.unprotectedHeader).toBeUndefined();
    expect(jwe.recipientUnprotectedHeader).toStrictEqual(algJkuKidHeader);

    expect(jwe.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from an Uncompressed Unprotected and Recipient Attached Token with no Additional Authenticated Data.', async () => {
    let jwe!: FlattenedJsonWebEncryption;

    await expect(
      async () => (jwe = await deserialize(uncompressedUnprotectedAndRecipientAttachedTokenNoAad, { jwk })),
    ).resolves.not.toThrow();

    expect(jwe.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.header.parameters).toStrictEqual(algEncJkuKidHeader);

    expect(jwe.protectedHeader).toBeUndefined();
    expect(jwe.unprotectedHeader).toStrictEqual(encHeader);
    expect(jwe.recipientUnprotectedHeader).toStrictEqual(algJkuKidHeader);

    expect(jwe.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from an Uncompressed Protected, Unprotected and Recipient Attached Token with no Additional Authenticated Data.', async () => {
    let jwe!: FlattenedJsonWebEncryption;

    await expect(
      async () => (jwe = await deserialize(uncompressedFullAttachedTokenNoAad, { jwk })),
    ).resolves.not.toThrow();

    expect(jwe.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.header.parameters).toStrictEqual(algEncJkuKidHeader);

    expect(jwe.protectedHeader).toStrictEqual(encHeader);
    expect(jwe.unprotectedHeader).toStrictEqual(jkuHeader);
    expect(jwe.recipientUnprotectedHeader).toStrictEqual(algKidHeader);

    expect(jwe.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from an Uncompressed Protected Detached Token with no Additional Authenticated Data.', async () => {
    let jwe!: FlattenedJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(uncompressedProtectedDetachedTokenNoAad, { jwk, detachedCiphertext: ciphertext });
    }).resolves.not.toThrow();

    expect(jwe.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.header.parameters).toStrictEqual(algEncJkuKidHeader);

    expect(jwe.protectedHeader).toStrictEqual(algEncJkuKidHeader);
    expect(jwe.unprotectedHeader).toBeUndefined();
    expect(jwe.recipientUnprotectedHeader).toBeUndefined();

    expect(jwe.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from an Uncompressed Unprotected Detached Token with no Additional Authenticated Data.', async () => {
    let jwe!: FlattenedJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(uncompressedUnprotectedDetachedTokenNoAad, { jwk, detachedCiphertext: ciphertext });
    }).resolves.not.toThrow();

    expect(jwe.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.header.parameters).toStrictEqual(algEncJkuKidHeader);

    expect(jwe.protectedHeader).toBeUndefined();
    expect(jwe.unprotectedHeader).toStrictEqual(algEncJkuKidHeader);
    expect(jwe.recipientUnprotectedHeader).toBeUndefined();

    expect(jwe.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from an Uncompressed Recipient Detached Token with no Additional Authenticated Data.', async () => {
    let jwe!: FlattenedJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(uncompressedRecipientDetachedTokenNoAad, { jwk, detachedCiphertext: ciphertext });
    }).resolves.not.toThrow();

    expect(jwe.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.header.parameters).toStrictEqual(algEncJkuKidHeader);

    expect(jwe.protectedHeader).toBeUndefined();
    expect(jwe.unprotectedHeader).toBeUndefined();
    expect(jwe.recipientUnprotectedHeader).toStrictEqual(algEncJkuKidHeader);

    expect(jwe.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from an Uncompressed Protected and Unprotected Detached Token with no Additional Authenticated Data.', async () => {
    let jwe!: FlattenedJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(uncompressedProtectedAndUnprotectedDetachedTokenNoAad, {
        jwk,
        detachedCiphertext: ciphertext,
      });
    }).resolves.not.toThrow();

    expect(jwe.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.header.parameters).toStrictEqual(algEncJkuKidHeader);

    expect(jwe.protectedHeader).toStrictEqual(encHeader);
    expect(jwe.unprotectedHeader).toStrictEqual(algJkuKidHeader);
    expect(jwe.recipientUnprotectedHeader).toBeUndefined();

    expect(jwe.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from an Uncompressed Protected and Recipient Detached Token with no Additional Authenticated Data.', async () => {
    let jwe!: FlattenedJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(uncompressedProtectedAndRecipientDetachedTokenNoAad, {
        jwk,
        detachedCiphertext: ciphertext,
      });
    }).resolves.not.toThrow();

    expect(jwe.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.header.parameters).toStrictEqual(algEncJkuKidHeader);

    expect(jwe.protectedHeader).toStrictEqual(encHeader);
    expect(jwe.unprotectedHeader).toBeUndefined();
    expect(jwe.recipientUnprotectedHeader).toStrictEqual(algJkuKidHeader);

    expect(jwe.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from an Uncompressed Unprotected and Recipient Detached Token with no Additional Authenticated Data.', async () => {
    let jwe!: FlattenedJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(uncompressedUnprotectedAndRecipientDetachedTokenNoAad, {
        jwk,
        detachedCiphertext: ciphertext,
      });
    }).resolves.not.toThrow();

    expect(jwe.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.header.parameters).toStrictEqual(algEncJkuKidHeader);

    expect(jwe.protectedHeader).toBeUndefined();
    expect(jwe.unprotectedHeader).toStrictEqual(encHeader);
    expect(jwe.recipientUnprotectedHeader).toStrictEqual(algJkuKidHeader);

    expect(jwe.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from an Uncompressed Protected, Unprotected and Recipient Detached Token with no Additional Authenticated Data.', async () => {
    let jwe!: FlattenedJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(uncompressedFullDetachedTokenNoAad, { jwk, detachedCiphertext: ciphertext });
    }).resolves.not.toThrow();

    expect(jwe.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.header.parameters).toStrictEqual(algEncJkuKidHeader);

    expect(jwe.protectedHeader).toStrictEqual(encHeader);
    expect(jwe.unprotectedHeader).toStrictEqual(jkuHeader);
    expect(jwe.recipientUnprotectedHeader).toStrictEqual(algKidHeader);

    expect(jwe.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from a Compressed Protected Attached Token with no Additional Authenticated Data.', async () => {
    let jwe!: FlattenedJsonWebEncryption;

    await expect(
      async () => (jwe = await deserialize(compressedProtectedAttachedTokenNoAad, { jwk })),
    ).resolves.not.toThrow();

    expect(jwe.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.header.parameters).toStrictEqual(algEncZipJkuKidHeader);

    expect(jwe.protectedHeader).toStrictEqual(algEncZipJkuKidHeader);
    expect(jwe.unprotectedHeader).toBeUndefined();
    expect(jwe.recipientUnprotectedHeader).toBeUndefined();

    expect(jwe.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from a Compressed Unprotected Attached Token with no Additional Authenticated Data.', async () => {
    let jwe!: FlattenedJsonWebEncryption;

    await expect(
      async () => (jwe = await deserialize(compressedUnprotectedAttachedTokenNoAad, { jwk })),
    ).resolves.not.toThrow();

    expect(jwe.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.header.parameters).toStrictEqual(algEncZipJkuKidHeader);

    expect(jwe.protectedHeader).toBeUndefined();
    expect(jwe.unprotectedHeader).toStrictEqual(algEncZipJkuKidHeader);
    expect(jwe.recipientUnprotectedHeader).toBeUndefined();

    expect(jwe.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from a Compressed Recipient Attached Token with no Additional Authenticated Data.', async () => {
    let jwe!: FlattenedJsonWebEncryption;

    await expect(
      async () => (jwe = await deserialize(compressedRecipientAttachedTokenNoAad, { jwk })),
    ).resolves.not.toThrow();

    expect(jwe.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.header.parameters).toStrictEqual(algEncZipJkuKidHeader);

    expect(jwe.protectedHeader).toBeUndefined();
    expect(jwe.unprotectedHeader).toBeUndefined();
    expect(jwe.recipientUnprotectedHeader).toStrictEqual(algEncZipJkuKidHeader);

    expect(jwe.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from a Compressed Protected and Unprotected Attached Token with no Additional Authenticated Data.', async () => {
    let jwe!: FlattenedJsonWebEncryption;

    await expect(
      async () => (jwe = await deserialize(compressedProtectedAndUnprotectedAttachedTokenNoAad, { jwk })),
    ).resolves.not.toThrow();

    expect(jwe.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.header.parameters).toStrictEqual(algEncZipJkuKidHeader);

    expect(jwe.protectedHeader).toStrictEqual(encHeader);
    expect(jwe.unprotectedHeader).toStrictEqual(algZipJkuKidHeader);
    expect(jwe.recipientUnprotectedHeader).toBeUndefined();

    expect(jwe.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from a Compressed Protected and Recipient Attached Token with no Additional Authenticated Data.', async () => {
    let jwe!: FlattenedJsonWebEncryption;

    await expect(
      async () => (jwe = await deserialize(compressedProtectedAndRecipientAttachedTokenNoAad, { jwk })),
    ).resolves.not.toThrow();

    expect(jwe.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.header.parameters).toStrictEqual(algEncZipJkuKidHeader);

    expect(jwe.protectedHeader).toStrictEqual(encHeader);
    expect(jwe.unprotectedHeader).toBeUndefined();
    expect(jwe.recipientUnprotectedHeader).toStrictEqual(algZipJkuKidHeader);

    expect(jwe.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from a Compressed Unprotected and Recipient Attached Token with no Additional Authenticated Data.', async () => {
    let jwe!: FlattenedJsonWebEncryption;

    await expect(
      async () => (jwe = await deserialize(compressedUnprotectedAndRecipientAttachedTokenNoAad, { jwk })),
    ).resolves.not.toThrow();

    expect(jwe.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.header.parameters).toStrictEqual(algEncZipJkuKidHeader);

    expect(jwe.protectedHeader).toBeUndefined();
    expect(jwe.unprotectedHeader).toStrictEqual(encHeader);
    expect(jwe.recipientUnprotectedHeader).toStrictEqual(algZipJkuKidHeader);

    expect(jwe.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from a Compressed Protected, Unprotected and Recipient Attached Token with no Additional Authenticated Data.', async () => {
    let jwe!: FlattenedJsonWebEncryption;

    await expect(
      async () => (jwe = await deserialize(compressedFullAttachedTokenNoAad, { jwk })),
    ).resolves.not.toThrow();

    expect(jwe.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.header.parameters).toStrictEqual(algEncZipJkuKidHeader);

    expect(jwe.protectedHeader).toStrictEqual(encHeader);
    expect(jwe.unprotectedHeader).toStrictEqual(jkuHeader);
    expect(jwe.recipientUnprotectedHeader).toStrictEqual(algZipKidHeader);

    expect(jwe.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from a Compressed Protected Detached Token with no Additional Authenticated Data.', async () => {
    let jwe!: FlattenedJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(compressedProtectedDetachedTokenNoAad, {
        jwk,
        detachedCiphertext: compressedCiphertext,
      });
    }).resolves.not.toThrow();

    expect(jwe.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.header.parameters).toStrictEqual(algEncZipJkuKidHeader);

    expect(jwe.protectedHeader).toStrictEqual(algEncZipJkuKidHeader);
    expect(jwe.unprotectedHeader).toBeUndefined();
    expect(jwe.recipientUnprotectedHeader).toBeUndefined();

    expect(jwe.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from a Compressed Unprotected Detached Token with no Additional Authenticated Data.', async () => {
    let jwe!: FlattenedJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(compressedUnprotectedDetachedTokenNoAad, {
        jwk,
        detachedCiphertext: compressedCiphertext,
      });
    }).resolves.not.toThrow();

    expect(jwe.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.header.parameters).toStrictEqual(algEncZipJkuKidHeader);

    expect(jwe.protectedHeader).toBeUndefined();
    expect(jwe.unprotectedHeader).toStrictEqual(algEncZipJkuKidHeader);
    expect(jwe.recipientUnprotectedHeader).toBeUndefined();

    expect(jwe.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from a Compressed Recipient Detached Token with no Additional Authenticated Data.', async () => {
    let jwe!: FlattenedJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(compressedRecipientDetachedTokenNoAad, {
        jwk,
        detachedCiphertext: compressedCiphertext,
      });
    }).resolves.not.toThrow();

    expect(jwe.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.header.parameters).toStrictEqual(algEncZipJkuKidHeader);

    expect(jwe.protectedHeader).toBeUndefined();
    expect(jwe.unprotectedHeader).toBeUndefined();
    expect(jwe.recipientUnprotectedHeader).toStrictEqual(algEncZipJkuKidHeader);

    expect(jwe.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from a Compressed Protected and Unprotected Detached Token with no Additional Authenticated Data.', async () => {
    let jwe!: FlattenedJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(compressedProtectedAndUnprotectedDetachedTokenNoAad, {
        jwk,
        detachedCiphertext: compressedCiphertext,
      });
    }).resolves.not.toThrow();

    expect(jwe.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.header.parameters).toStrictEqual(algEncZipJkuKidHeader);

    expect(jwe.protectedHeader).toStrictEqual(encHeader);
    expect(jwe.unprotectedHeader).toStrictEqual(algZipJkuKidHeader);
    expect(jwe.recipientUnprotectedHeader).toBeUndefined();

    expect(jwe.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from a Compressed Protected and Recipient Detached Token with no Additional Authenticated Data.', async () => {
    let jwe!: FlattenedJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(compressedProtectedAndRecipientDetachedTokenNoAad, {
        jwk,
        detachedCiphertext: compressedCiphertext,
      });
    }).resolves.not.toThrow();

    expect(jwe.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.header.parameters).toStrictEqual(algEncZipJkuKidHeader);

    expect(jwe.protectedHeader).toStrictEqual(encHeader);
    expect(jwe.unprotectedHeader).toBeUndefined();
    expect(jwe.recipientUnprotectedHeader).toStrictEqual(algZipJkuKidHeader);

    expect(jwe.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from a Compressed Unprotected and Recipient Detached Token with no Additional Authenticated Data.', async () => {
    let jwe!: FlattenedJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(compressedUnprotectedAndRecipientDetachedTokenNoAad, {
        jwk,
        detachedCiphertext: compressedCiphertext,
      });
    }).resolves.not.toThrow();

    expect(jwe.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.header.parameters).toStrictEqual(algEncZipJkuKidHeader);

    expect(jwe.protectedHeader).toBeUndefined();
    expect(jwe.unprotectedHeader).toStrictEqual(encHeader);
    expect(jwe.recipientUnprotectedHeader).toStrictEqual(algZipJkuKidHeader);

    expect(jwe.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from a Compressed Protected, Unprotected and Recipient Detached Token with no Additional Authenticated Data.', async () => {
    let jwe!: FlattenedJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(compressedFullDetachedTokenNoAad, { jwk, detachedCiphertext: compressedCiphertext });
    }).resolves.not.toThrow();

    expect(jwe.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.header.parameters).toStrictEqual(algEncZipJkuKidHeader);

    expect(jwe.protectedHeader).toStrictEqual(encHeader);
    expect(jwe.unprotectedHeader).toStrictEqual(jkuHeader);
    expect(jwe.recipientUnprotectedHeader).toStrictEqual(algZipKidHeader);

    expect(jwe.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from an Uncompressed Protected Attached Token with Additional Authenticated Data.', async () => {
    let jwe!: FlattenedJsonWebEncryption;

    await expect(
      async () => (jwe = await deserialize(uncompressedProtectedAttachedToken, { jwk })),
    ).resolves.not.toThrow();

    expect(jwe.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.header.parameters).toStrictEqual(algEncJkuKidHeader);

    expect(jwe.protectedHeader).toStrictEqual(algEncJkuKidHeader);
    expect(jwe.unprotectedHeader).toBeUndefined();
    expect(jwe.recipientUnprotectedHeader).toBeUndefined();

    expect(jwe.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from an Uncompressed Unprotected Attached Token with Additional Authenticated Data.', async () => {
    let jwe!: FlattenedJsonWebEncryption;

    await expect(
      async () => (jwe = await deserialize(uncompressedUnprotectedAttachedToken, { jwk })),
    ).resolves.not.toThrow();

    expect(jwe.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.header.parameters).toStrictEqual(algEncJkuKidHeader);

    expect(jwe.protectedHeader).toBeUndefined();
    expect(jwe.unprotectedHeader).toStrictEqual(algEncJkuKidHeader);
    expect(jwe.recipientUnprotectedHeader).toBeUndefined();

    expect(jwe.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from an Uncompressed Recipient Attached Token with Additional Authenticated Data.', async () => {
    let jwe!: FlattenedJsonWebEncryption;

    await expect(
      async () => (jwe = await deserialize(uncompressedRecipientAttachedToken, { jwk })),
    ).resolves.not.toThrow();

    expect(jwe.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.header.parameters).toStrictEqual(algEncJkuKidHeader);

    expect(jwe.protectedHeader).toBeUndefined();
    expect(jwe.unprotectedHeader).toBeUndefined();
    expect(jwe.recipientUnprotectedHeader).toStrictEqual(algEncJkuKidHeader);

    expect(jwe.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from an Uncompressed Protected and Unprotected Attached Token with Additional Authenticated Data.', async () => {
    let jwe!: FlattenedJsonWebEncryption;

    await expect(
      async () => (jwe = await deserialize(uncompressedProtectedAndUnprotectedAttachedToken, { jwk })),
    ).resolves.not.toThrow();

    expect(jwe.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.header.parameters).toStrictEqual(algEncJkuKidHeader);

    expect(jwe.protectedHeader).toStrictEqual(encHeader);
    expect(jwe.unprotectedHeader).toStrictEqual(algJkuKidHeader);
    expect(jwe.recipientUnprotectedHeader).toBeUndefined();

    expect(jwe.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from an Uncompressed Protected and Recipient Attached Token with Additional Authenticated Data.', async () => {
    let jwe!: FlattenedJsonWebEncryption;

    await expect(
      async () => (jwe = await deserialize(uncompressedProtectedAndRecipientAttachedToken, { jwk })),
    ).resolves.not.toThrow();

    expect(jwe.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.header.parameters).toStrictEqual(algEncJkuKidHeader);

    expect(jwe.protectedHeader).toStrictEqual(encHeader);
    expect(jwe.unprotectedHeader).toBeUndefined();
    expect(jwe.recipientUnprotectedHeader).toStrictEqual(algJkuKidHeader);

    expect(jwe.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from an Uncompressed Unprotected and Recipient Attached Token with Additional Authenticated Data.', async () => {
    let jwe!: FlattenedJsonWebEncryption;

    await expect(
      async () => (jwe = await deserialize(uncompressedUnprotectedAndRecipientAttachedToken, { jwk })),
    ).resolves.not.toThrow();

    expect(jwe.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.header.parameters).toStrictEqual(algEncJkuKidHeader);

    expect(jwe.protectedHeader).toBeUndefined();
    expect(jwe.unprotectedHeader).toStrictEqual(encHeader);
    expect(jwe.recipientUnprotectedHeader).toStrictEqual(algJkuKidHeader);

    expect(jwe.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from an Uncompressed Protected, Unprotected and Recipient Attached Token with Additional Authenticated Data.', async () => {
    let jwe!: FlattenedJsonWebEncryption;

    await expect(async () => (jwe = await deserialize(uncompressedFullAttachedToken, { jwk }))).resolves.not.toThrow();

    expect(jwe.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.header.parameters).toStrictEqual(algEncJkuKidHeader);

    expect(jwe.protectedHeader).toStrictEqual(encHeader);
    expect(jwe.unprotectedHeader).toStrictEqual(jkuHeader);
    expect(jwe.recipientUnprotectedHeader).toStrictEqual(algKidHeader);

    expect(jwe.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from an Uncompressed Protected Detached Token with Additional Authenticated Data.', async () => {
    let jwe!: FlattenedJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(uncompressedProtectedDetachedToken, { jwk, detachedCiphertext: ciphertext });
    }).resolves.not.toThrow();

    expect(jwe.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.header.parameters).toStrictEqual(algEncJkuKidHeader);

    expect(jwe.protectedHeader).toStrictEqual(algEncJkuKidHeader);
    expect(jwe.unprotectedHeader).toBeUndefined();
    expect(jwe.recipientUnprotectedHeader).toBeUndefined();

    expect(jwe.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from an Uncompressed Unprotected Detached Token with Additional Authenticated Data.', async () => {
    let jwe!: FlattenedJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(uncompressedUnprotectedDetachedToken, { jwk, detachedCiphertext: ciphertext });
    }).resolves.not.toThrow();

    expect(jwe.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.header.parameters).toStrictEqual(algEncJkuKidHeader);

    expect(jwe.protectedHeader).toBeUndefined();
    expect(jwe.unprotectedHeader).toStrictEqual(algEncJkuKidHeader);
    expect(jwe.recipientUnprotectedHeader).toBeUndefined();

    expect(jwe.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from an Uncompressed Recipient Detached Token with Additional Authenticated Data.', async () => {
    let jwe!: FlattenedJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(uncompressedRecipientDetachedToken, { jwk, detachedCiphertext: ciphertext });
    }).resolves.not.toThrow();

    expect(jwe.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.header.parameters).toStrictEqual(algEncJkuKidHeader);

    expect(jwe.protectedHeader).toBeUndefined();
    expect(jwe.unprotectedHeader).toBeUndefined();
    expect(jwe.recipientUnprotectedHeader).toStrictEqual(algEncJkuKidHeader);

    expect(jwe.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from an Uncompressed Protected and Unprotected Detached Token with Additional Authenticated Data.', async () => {
    let jwe!: FlattenedJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(uncompressedProtectedAndUnprotectedDetachedToken, {
        jwk,
        detachedCiphertext: ciphertext,
      });
    }).resolves.not.toThrow();

    expect(jwe.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.header.parameters).toStrictEqual(algEncJkuKidHeader);

    expect(jwe.protectedHeader).toStrictEqual(encHeader);
    expect(jwe.unprotectedHeader).toStrictEqual(algJkuKidHeader);
    expect(jwe.recipientUnprotectedHeader).toBeUndefined();

    expect(jwe.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from an Uncompressed Protected and Recipient Detached Token with Additional Authenticated Data.', async () => {
    let jwe!: FlattenedJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(uncompressedProtectedAndRecipientDetachedToken, {
        jwk,
        detachedCiphertext: ciphertext,
      });
    }).resolves.not.toThrow();

    expect(jwe.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.header.parameters).toStrictEqual(algEncJkuKidHeader);

    expect(jwe.protectedHeader).toStrictEqual(encHeader);
    expect(jwe.unprotectedHeader).toBeUndefined();
    expect(jwe.recipientUnprotectedHeader).toStrictEqual(algJkuKidHeader);

    expect(jwe.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from an Uncompressed Unprotected and Recipient Detached Token with Additional Authenticated Data.', async () => {
    let jwe!: FlattenedJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(uncompressedUnprotectedAndRecipientDetachedToken, {
        jwk,
        detachedCiphertext: ciphertext,
      });
    }).resolves.not.toThrow();

    expect(jwe.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.header.parameters).toStrictEqual(algEncJkuKidHeader);

    expect(jwe.protectedHeader).toBeUndefined();
    expect(jwe.unprotectedHeader).toStrictEqual(encHeader);
    expect(jwe.recipientUnprotectedHeader).toStrictEqual(algJkuKidHeader);

    expect(jwe.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from an Uncompressed Protected, Unprotected and Recipient Detached Token with Additional Authenticated Data.', async () => {
    let jwe!: FlattenedJsonWebEncryption;

    await expect(
      async () => (jwe = await deserialize(uncompressedFullDetachedToken, { jwk, detachedCiphertext: ciphertext })),
    ).resolves.not.toThrow();

    expect(jwe.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.header.parameters).toStrictEqual(algEncJkuKidHeader);

    expect(jwe.protectedHeader).toStrictEqual(encHeader);
    expect(jwe.unprotectedHeader).toStrictEqual(jkuHeader);
    expect(jwe.recipientUnprotectedHeader).toStrictEqual(algKidHeader);

    expect(jwe.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from a Compressed Protected Attached Token with Additional Authenticated Data.', async () => {
    let jwe!: FlattenedJsonWebEncryption;

    await expect(
      async () => (jwe = await deserialize(compressedProtectedAttachedToken, { jwk })),
    ).resolves.not.toThrow();

    expect(jwe.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.header.parameters).toStrictEqual(algEncZipJkuKidHeader);

    expect(jwe.protectedHeader).toStrictEqual(algEncZipJkuKidHeader);
    expect(jwe.unprotectedHeader).toBeUndefined();
    expect(jwe.recipientUnprotectedHeader).toBeUndefined();

    expect(jwe.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from a Compressed Unprotected Attached Token with Additional Authenticated Data.', async () => {
    let jwe!: FlattenedJsonWebEncryption;

    await expect(
      async () => (jwe = await deserialize(compressedUnprotectedAttachedToken, { jwk })),
    ).resolves.not.toThrow();

    expect(jwe.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.header.parameters).toStrictEqual(algEncZipJkuKidHeader);

    expect(jwe.protectedHeader).toBeUndefined();
    expect(jwe.unprotectedHeader).toStrictEqual(algEncZipJkuKidHeader);
    expect(jwe.recipientUnprotectedHeader).toBeUndefined();

    expect(jwe.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from a Compressed Recipient Attached Token with Additional Authenticated Data.', async () => {
    let jwe!: FlattenedJsonWebEncryption;

    await expect(
      async () => (jwe = await deserialize(compressedRecipientAttachedToken, { jwk })),
    ).resolves.not.toThrow();

    expect(jwe.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.header.parameters).toStrictEqual(algEncZipJkuKidHeader);

    expect(jwe.protectedHeader).toBeUndefined();
    expect(jwe.unprotectedHeader).toBeUndefined();
    expect(jwe.recipientUnprotectedHeader).toStrictEqual(algEncZipJkuKidHeader);

    expect(jwe.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from a Compressed Protected and Unprotected Attached Token with Additional Authenticated Data.', async () => {
    let jwe!: FlattenedJsonWebEncryption;

    await expect(
      async () => (jwe = await deserialize(compressedProtectedAndUnprotectedAttachedToken, { jwk })),
    ).resolves.not.toThrow();

    expect(jwe.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.header.parameters).toStrictEqual(algEncZipJkuKidHeader);

    expect(jwe.protectedHeader).toStrictEqual(encHeader);
    expect(jwe.unprotectedHeader).toStrictEqual(algZipJkuKidHeader);
    expect(jwe.recipientUnprotectedHeader).toBeUndefined();

    expect(jwe.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from a Compressed Protected and Recipient Attached Token with Additional Authenticated Data.', async () => {
    let jwe!: FlattenedJsonWebEncryption;

    await expect(
      async () => (jwe = await deserialize(compressedProtectedAndRecipientAttachedToken, { jwk })),
    ).resolves.not.toThrow();

    expect(jwe.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.header.parameters).toStrictEqual(algEncZipJkuKidHeader);

    expect(jwe.protectedHeader).toStrictEqual(encHeader);
    expect(jwe.unprotectedHeader).toBeUndefined();
    expect(jwe.recipientUnprotectedHeader).toStrictEqual(algZipJkuKidHeader);

    expect(jwe.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from a Compressed Unprotected and Recipient Attached Token with Additional Authenticated Data.', async () => {
    let jwe!: FlattenedJsonWebEncryption;

    await expect(
      async () => (jwe = await deserialize(compressedUnprotectedAndRecipientAttachedToken, { jwk })),
    ).resolves.not.toThrow();

    expect(jwe.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.header.parameters).toStrictEqual(algEncZipJkuKidHeader);

    expect(jwe.protectedHeader).toBeUndefined();
    expect(jwe.unprotectedHeader).toStrictEqual(encHeader);
    expect(jwe.recipientUnprotectedHeader).toStrictEqual(algZipJkuKidHeader);

    expect(jwe.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from a Compressed Protected, Unprotected and Recipient Attached Token with Additional Authenticated Data.', async () => {
    let jwe!: FlattenedJsonWebEncryption;

    await expect(async () => (jwe = await deserialize(compressedFullAttachedToken, { jwk }))).resolves.not.toThrow();

    expect(jwe.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.header.parameters).toStrictEqual(algEncZipJkuKidHeader);

    expect(jwe.protectedHeader).toStrictEqual(encHeader);
    expect(jwe.unprotectedHeader).toStrictEqual(jkuHeader);
    expect(jwe.recipientUnprotectedHeader).toStrictEqual(algZipKidHeader);

    expect(jwe.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from a Compressed Protected Detached Token with Additional Authenticated Data.', async () => {
    let jwe!: FlattenedJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(compressedProtectedDetachedToken, { jwk, detachedCiphertext: compressedCiphertext });
    }).resolves.not.toThrow();

    expect(jwe.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.header.parameters).toStrictEqual(algEncZipJkuKidHeader);

    expect(jwe.protectedHeader).toStrictEqual(algEncZipJkuKidHeader);
    expect(jwe.unprotectedHeader).toBeUndefined();
    expect(jwe.recipientUnprotectedHeader).toBeUndefined();

    expect(jwe.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from a Compressed Unprotected Detached Token with Additional Authenticated Data.', async () => {
    let jwe!: FlattenedJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(compressedUnprotectedDetachedToken, {
        jwk,
        detachedCiphertext: compressedCiphertext,
      });
    }).resolves.not.toThrow();

    expect(jwe.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.header.parameters).toStrictEqual(algEncZipJkuKidHeader);

    expect(jwe.protectedHeader).toBeUndefined();
    expect(jwe.unprotectedHeader).toStrictEqual(algEncZipJkuKidHeader);
    expect(jwe.recipientUnprotectedHeader).toBeUndefined();

    expect(jwe.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from a Compressed Recipient Detached Token with Additional Authenticated Data.', async () => {
    let jwe!: FlattenedJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(compressedRecipientDetachedToken, { jwk, detachedCiphertext: compressedCiphertext });
    }).resolves.not.toThrow();

    expect(jwe.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.header.parameters).toStrictEqual(algEncZipJkuKidHeader);

    expect(jwe.protectedHeader).toBeUndefined();
    expect(jwe.unprotectedHeader).toBeUndefined();
    expect(jwe.recipientUnprotectedHeader).toStrictEqual(algEncZipJkuKidHeader);

    expect(jwe.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from a Compressed Protected and Unprotected Detached Token with Additional Authenticated Data.', async () => {
    let jwe!: FlattenedJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(compressedProtectedAndUnprotectedDetachedToken, {
        jwk,
        detachedCiphertext: compressedCiphertext,
      });
    }).resolves.not.toThrow();

    expect(jwe.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.header.parameters).toStrictEqual(algEncZipJkuKidHeader);

    expect(jwe.protectedHeader).toStrictEqual(encHeader);
    expect(jwe.unprotectedHeader).toStrictEqual(algZipJkuKidHeader);
    expect(jwe.recipientUnprotectedHeader).toBeUndefined();

    expect(jwe.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from a Compressed Protected and Recipient Detached Token with Additional Authenticated Data.', async () => {
    let jwe!: FlattenedJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(compressedProtectedAndRecipientDetachedToken, {
        jwk,
        detachedCiphertext: compressedCiphertext,
      });
    }).resolves.not.toThrow();

    expect(jwe.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.header.parameters).toStrictEqual(algEncZipJkuKidHeader);

    expect(jwe.protectedHeader).toStrictEqual(encHeader);
    expect(jwe.unprotectedHeader).toBeUndefined();
    expect(jwe.recipientUnprotectedHeader).toStrictEqual(algZipJkuKidHeader);

    expect(jwe.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from a Compressed Unprotected and Recipient Detached Token with Additional Authenticated Data.', async () => {
    let jwe!: FlattenedJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(compressedUnprotectedAndRecipientDetachedToken, {
        jwk,
        detachedCiphertext: compressedCiphertext,
      });
    }).resolves.not.toThrow();

    expect(jwe.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.header.parameters).toStrictEqual(algEncZipJkuKidHeader);

    expect(jwe.protectedHeader).toBeUndefined();
    expect(jwe.unprotectedHeader).toStrictEqual(encHeader);
    expect(jwe.recipientUnprotectedHeader).toStrictEqual(algZipJkuKidHeader);

    expect(jwe.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from a Compressed Protected, Unprotected and Recipient Detached Token with Additional Authenticated Data.', async () => {
    let jwe!: FlattenedJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(compressedFullDetachedToken, { jwk, detachedCiphertext: compressedCiphertext });
    }).resolves.not.toThrow();

    expect(jwe.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.header.parameters).toStrictEqual(algEncZipJkuKidHeader);

    expect(jwe.protectedHeader).toStrictEqual(encHeader);
    expect(jwe.unprotectedHeader).toStrictEqual(jkuHeader);
    expect(jwe.recipientUnprotectedHeader).toStrictEqual(algZipKidHeader);

    expect(jwe.plaintext).toStrictEqual(plaintext);
  });
});
