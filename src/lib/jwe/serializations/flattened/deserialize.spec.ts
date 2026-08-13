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

const invalidExpectedAlgorithms: any[] = [
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
  ['a'],
];

const invalidDetachedCiphertexts: any[] = [
  undefined,
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
  const wrongEncryptedKeyToken: FlattenedJsonWebEncryptionToken = {
    protected: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    unprotected: { jku: 'https://server.example.com/keys.jwks' },
    header: { alg: 'A128KW', kid: '7' },
    encrypted_key: 'anBl9PSuJobKWwzWzJCqfMnejCvM5-WadN3zXMGyoCLW8_xmUldY3Q',
    aad: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    ciphertext: 'KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY',
    tag: 'U0m_YmjN04DJvceFICbCVQ',
  };

  const wrongAdditionalAuthenticatedDataToken: FlattenedJsonWebEncryptionToken = {
    protected: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    unprotected: { jku: 'https://server.example.com/keys.jwks' },
    header: { alg: 'A128KW', kid: '7' },
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: 'eyJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    ciphertext: 'KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY',
    tag: 'U0m_YmjN04DJvceFICbCVQ',
  };

  const wrongInitializationVectorToken: FlattenedJsonWebEncryptionToken = {
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

  const wrongAuthenticationTagToken: FlattenedJsonWebEncryptionToken = {
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

  const jsonWebKey = new OctetSequenceJsonWebKey({ kty: 'oct', k: 'GawgguFyGrWKav7AX4VKUg', kid: '7' });

  beforeEach(() => {
    https.get = jest.fn().mockImplementation((_, cb) => {
      const stream = new Stream();
      cb(stream);
      stream.emit('data', jsonStringify({ keys: [jsonWebKey.parameters] }));
      stream.emit('end');
    });
  });

  it.each(invalidDeserializeOptions)('should throw when the provided options is invalid.', async (options) => {
    await expect(deserialize(uncompressedProtectedAttachedTokenNoAad, options)).rejects.toThrowWithMessage(
      TypeError,
      'The provided options is invalid.',
    );
  });

  it.each(invalidJsonWebKeys)('should throw when the provided option "jsonWebKey" is invalid.', async (jsonWebKey) => {
    await expect(deserialize(uncompressedProtectedAttachedTokenNoAad, { jsonWebKey })).rejects.toThrowWithMessage(
      TypeError,
      'The provided option "jsonWebKey" is invalid.',
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
    await expect(deserialize(wrongEncryptedKeyToken, { jsonWebKey })).rejects.toThrow();
  });

  it('should throw when the provided Additional Authenticated Data fails to deserialize the provided Flattened JSON Web Encryption Token.', async () => {
    await expect(deserialize(wrongAdditionalAuthenticatedDataToken, { jsonWebKey })).rejects.toThrow();
  });

  it('should throw when the provided Initialization Vector fails to deserialize the provided Flattened JSON Web Encryption Token.', async () => {
    await expect(deserialize(wrongInitializationVectorToken, { jsonWebKey })).rejects.toThrow();
  });

  it('should throw when the provided Ciphertext fails to deserialize the provided Flattened JSON Web Encryption Token.', async () => {
    await expect(deserialize(wrongCiphertextToken, { jsonWebKey })).rejects.toThrow();
  });

  it('should throw when the provided Authentication Tag fails to deserialize the provided Flattened JSON Web Encryption Token.', async () => {
    await expect(deserialize(wrongAuthenticationTagToken, { jsonWebKey })).rejects.toThrow();
  });

  it('should return the deserialized Flattened JSON Web Encryption from an Uncompressed Protected Attached Token with no Additional Authenticated Data.', async () => {
    let jsonWebEncryption!: FlattenedJsonWebEncryption;

    await expect(async () => {
      jsonWebEncryption = await deserialize(uncompressedProtectedAttachedTokenNoAad, { jsonWebKey });
    }).resolves.not.toThrow();

    expect(jsonWebEncryption.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jsonWebEncryption.header.parameters).toStrictEqual(algEncJkuKidHeader);

    expect(jsonWebEncryption.protectedHeader).toStrictEqual(algEncJkuKidHeader);
    expect(jsonWebEncryption.unprotectedHeader).toBeUndefined();
    expect(jsonWebEncryption.recipientUnprotectedHeader).toBeUndefined();

    expect(jsonWebEncryption.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from an Uncompressed Unprotected Attached Token with no Additional Authenticated Data.', async () => {
    let jsonWebEncryption!: FlattenedJsonWebEncryption;

    await expect(async () => {
      jsonWebEncryption = await deserialize(uncompressedUnprotectedAttachedTokenNoAad, { jsonWebKey });
    }).resolves.not.toThrow();

    expect(jsonWebEncryption.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jsonWebEncryption.header.parameters).toStrictEqual(algEncJkuKidHeader);

    expect(jsonWebEncryption.protectedHeader).toBeUndefined();
    expect(jsonWebEncryption.unprotectedHeader).toStrictEqual(algEncJkuKidHeader);
    expect(jsonWebEncryption.recipientUnprotectedHeader).toBeUndefined();

    expect(jsonWebEncryption.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from an Uncompressed Recipient Attached Token with no Additional Authenticated Data.', async () => {
    let jsonWebEncryption!: FlattenedJsonWebEncryption;

    await expect(async () => {
      jsonWebEncryption = await deserialize(uncompressedRecipientAttachedTokenNoAad, { jsonWebKey });
    }).resolves.not.toThrow();

    expect(jsonWebEncryption.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jsonWebEncryption.header.parameters).toStrictEqual(algEncJkuKidHeader);

    expect(jsonWebEncryption.protectedHeader).toBeUndefined();
    expect(jsonWebEncryption.unprotectedHeader).toBeUndefined();
    expect(jsonWebEncryption.recipientUnprotectedHeader).toStrictEqual(algEncJkuKidHeader);

    expect(jsonWebEncryption.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from an Uncompressed Protected and Unprotected Attached Token with no Additional Authenticated Data.', async () => {
    let jsonWebEncryption!: FlattenedJsonWebEncryption;

    await expect(
      async () =>
        (jsonWebEncryption = await deserialize(uncompressedProtectedAndUnprotectedAttachedTokenNoAad, { jsonWebKey })),
    ).resolves.not.toThrow();

    expect(jsonWebEncryption.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jsonWebEncryption.header.parameters).toStrictEqual(algEncJkuKidHeader);

    expect(jsonWebEncryption.protectedHeader).toStrictEqual(encHeader);
    expect(jsonWebEncryption.unprotectedHeader).toStrictEqual(algJkuKidHeader);
    expect(jsonWebEncryption.recipientUnprotectedHeader).toBeUndefined();

    expect(jsonWebEncryption.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from an Uncompressed Protected and Recipient Attached Token with no Additional Authenticated Data.', async () => {
    let jsonWebEncryption!: FlattenedJsonWebEncryption;

    await expect(
      async () =>
        (jsonWebEncryption = await deserialize(uncompressedProtectedAndRecipientAttachedTokenNoAad, { jsonWebKey })),
    ).resolves.not.toThrow();

    expect(jsonWebEncryption.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jsonWebEncryption.header.parameters).toStrictEqual(algEncJkuKidHeader);

    expect(jsonWebEncryption.protectedHeader).toStrictEqual(encHeader);
    expect(jsonWebEncryption.unprotectedHeader).toBeUndefined();
    expect(jsonWebEncryption.recipientUnprotectedHeader).toStrictEqual(algJkuKidHeader);

    expect(jsonWebEncryption.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from an Uncompressed Unprotected and Recipient Attached Token with no Additional Authenticated Data.', async () => {
    let jsonWebEncryption!: FlattenedJsonWebEncryption;

    await expect(
      async () =>
        (jsonWebEncryption = await deserialize(uncompressedUnprotectedAndRecipientAttachedTokenNoAad, { jsonWebKey })),
    ).resolves.not.toThrow();

    expect(jsonWebEncryption.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jsonWebEncryption.header.parameters).toStrictEqual(algEncJkuKidHeader);

    expect(jsonWebEncryption.protectedHeader).toBeUndefined();
    expect(jsonWebEncryption.unprotectedHeader).toStrictEqual(encHeader);
    expect(jsonWebEncryption.recipientUnprotectedHeader).toStrictEqual(algJkuKidHeader);

    expect(jsonWebEncryption.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from an Uncompressed Protected, Unprotected and Recipient Attached Token with no Additional Authenticated Data.', async () => {
    let jsonWebEncryption!: FlattenedJsonWebEncryption;

    await expect(async () => {
      jsonWebEncryption = await deserialize(uncompressedFullAttachedTokenNoAad, { jsonWebKey });
    }).resolves.not.toThrow();

    expect(jsonWebEncryption.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jsonWebEncryption.header.parameters).toStrictEqual(algEncJkuKidHeader);

    expect(jsonWebEncryption.protectedHeader).toStrictEqual(encHeader);
    expect(jsonWebEncryption.unprotectedHeader).toStrictEqual(jkuHeader);
    expect(jsonWebEncryption.recipientUnprotectedHeader).toStrictEqual(algKidHeader);

    expect(jsonWebEncryption.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from an Uncompressed Protected Detached Token with no Additional Authenticated Data.', async () => {
    let jsonWebEncryption!: FlattenedJsonWebEncryption;

    await expect(async () => {
      jsonWebEncryption = await deserialize(uncompressedProtectedDetachedTokenNoAad, {
        jsonWebKey,
        detachedCiphertext: ciphertext,
      });
    }).resolves.not.toThrow();

    expect(jsonWebEncryption.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jsonWebEncryption.header.parameters).toStrictEqual(algEncJkuKidHeader);

    expect(jsonWebEncryption.protectedHeader).toStrictEqual(algEncJkuKidHeader);
    expect(jsonWebEncryption.unprotectedHeader).toBeUndefined();
    expect(jsonWebEncryption.recipientUnprotectedHeader).toBeUndefined();

    expect(jsonWebEncryption.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from an Uncompressed Unprotected Detached Token with no Additional Authenticated Data.', async () => {
    let jsonWebEncryption!: FlattenedJsonWebEncryption;

    await expect(async () => {
      jsonWebEncryption = await deserialize(uncompressedUnprotectedDetachedTokenNoAad, {
        jsonWebKey,
        detachedCiphertext: ciphertext,
      });
    }).resolves.not.toThrow();

    expect(jsonWebEncryption.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jsonWebEncryption.header.parameters).toStrictEqual(algEncJkuKidHeader);

    expect(jsonWebEncryption.protectedHeader).toBeUndefined();
    expect(jsonWebEncryption.unprotectedHeader).toStrictEqual(algEncJkuKidHeader);
    expect(jsonWebEncryption.recipientUnprotectedHeader).toBeUndefined();

    expect(jsonWebEncryption.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from an Uncompressed Recipient Detached Token with no Additional Authenticated Data.', async () => {
    let jsonWebEncryption!: FlattenedJsonWebEncryption;

    await expect(async () => {
      jsonWebEncryption = await deserialize(uncompressedRecipientDetachedTokenNoAad, {
        jsonWebKey,
        detachedCiphertext: ciphertext,
      });
    }).resolves.not.toThrow();

    expect(jsonWebEncryption.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jsonWebEncryption.header.parameters).toStrictEqual(algEncJkuKidHeader);

    expect(jsonWebEncryption.protectedHeader).toBeUndefined();
    expect(jsonWebEncryption.unprotectedHeader).toBeUndefined();
    expect(jsonWebEncryption.recipientUnprotectedHeader).toStrictEqual(algEncJkuKidHeader);

    expect(jsonWebEncryption.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from an Uncompressed Protected and Unprotected Detached Token with no Additional Authenticated Data.', async () => {
    let jsonWebEncryption!: FlattenedJsonWebEncryption;

    await expect(async () => {
      jsonWebEncryption = await deserialize(uncompressedProtectedAndUnprotectedDetachedTokenNoAad, {
        jsonWebKey,
        detachedCiphertext: ciphertext,
      });
    }).resolves.not.toThrow();

    expect(jsonWebEncryption.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jsonWebEncryption.header.parameters).toStrictEqual(algEncJkuKidHeader);

    expect(jsonWebEncryption.protectedHeader).toStrictEqual(encHeader);
    expect(jsonWebEncryption.unprotectedHeader).toStrictEqual(algJkuKidHeader);
    expect(jsonWebEncryption.recipientUnprotectedHeader).toBeUndefined();

    expect(jsonWebEncryption.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from an Uncompressed Protected and Recipient Detached Token with no Additional Authenticated Data.', async () => {
    let jsonWebEncryption!: FlattenedJsonWebEncryption;

    await expect(async () => {
      jsonWebEncryption = await deserialize(uncompressedProtectedAndRecipientDetachedTokenNoAad, {
        jsonWebKey,
        detachedCiphertext: ciphertext,
      });
    }).resolves.not.toThrow();

    expect(jsonWebEncryption.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jsonWebEncryption.header.parameters).toStrictEqual(algEncJkuKidHeader);

    expect(jsonWebEncryption.protectedHeader).toStrictEqual(encHeader);
    expect(jsonWebEncryption.unprotectedHeader).toBeUndefined();
    expect(jsonWebEncryption.recipientUnprotectedHeader).toStrictEqual(algJkuKidHeader);

    expect(jsonWebEncryption.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from an Uncompressed Unprotected and Recipient Detached Token with no Additional Authenticated Data.', async () => {
    let jsonWebEncryption!: FlattenedJsonWebEncryption;

    await expect(async () => {
      jsonWebEncryption = await deserialize(uncompressedUnprotectedAndRecipientDetachedTokenNoAad, {
        jsonWebKey,
        detachedCiphertext: ciphertext,
      });
    }).resolves.not.toThrow();

    expect(jsonWebEncryption.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jsonWebEncryption.header.parameters).toStrictEqual(algEncJkuKidHeader);

    expect(jsonWebEncryption.protectedHeader).toBeUndefined();
    expect(jsonWebEncryption.unprotectedHeader).toStrictEqual(encHeader);
    expect(jsonWebEncryption.recipientUnprotectedHeader).toStrictEqual(algJkuKidHeader);

    expect(jsonWebEncryption.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from an Uncompressed Protected, Unprotected and Recipient Detached Token with no Additional Authenticated Data.', async () => {
    let jsonWebEncryption!: FlattenedJsonWebEncryption;

    await expect(async () => {
      jsonWebEncryption = await deserialize(uncompressedFullDetachedTokenNoAad, {
        jsonWebKey,
        detachedCiphertext: ciphertext,
      });
    }).resolves.not.toThrow();

    expect(jsonWebEncryption.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jsonWebEncryption.header.parameters).toStrictEqual(algEncJkuKidHeader);

    expect(jsonWebEncryption.protectedHeader).toStrictEqual(encHeader);
    expect(jsonWebEncryption.unprotectedHeader).toStrictEqual(jkuHeader);
    expect(jsonWebEncryption.recipientUnprotectedHeader).toStrictEqual(algKidHeader);

    expect(jsonWebEncryption.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from a Compressed Protected Attached Token with no Additional Authenticated Data.', async () => {
    let jsonWebEncryption!: FlattenedJsonWebEncryption;

    await expect(async () => {
      jsonWebEncryption = await deserialize(compressedProtectedAttachedTokenNoAad, { jsonWebKey });
    }).resolves.not.toThrow();

    expect(jsonWebEncryption.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jsonWebEncryption.header.parameters).toStrictEqual(algEncZipJkuKidHeader);

    expect(jsonWebEncryption.protectedHeader).toStrictEqual(algEncZipJkuKidHeader);
    expect(jsonWebEncryption.unprotectedHeader).toBeUndefined();
    expect(jsonWebEncryption.recipientUnprotectedHeader).toBeUndefined();

    expect(jsonWebEncryption.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from a Compressed Unprotected Attached Token with no Additional Authenticated Data.', async () => {
    let jsonWebEncryption!: FlattenedJsonWebEncryption;

    await expect(async () => {
      jsonWebEncryption = await deserialize(compressedUnprotectedAttachedTokenNoAad, { jsonWebKey });
    }).resolves.not.toThrow();

    expect(jsonWebEncryption.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jsonWebEncryption.header.parameters).toStrictEqual(algEncZipJkuKidHeader);

    expect(jsonWebEncryption.protectedHeader).toBeUndefined();
    expect(jsonWebEncryption.unprotectedHeader).toStrictEqual(algEncZipJkuKidHeader);
    expect(jsonWebEncryption.recipientUnprotectedHeader).toBeUndefined();

    expect(jsonWebEncryption.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from a Compressed Recipient Attached Token with no Additional Authenticated Data.', async () => {
    let jsonWebEncryption!: FlattenedJsonWebEncryption;

    await expect(async () => {
      jsonWebEncryption = await deserialize(compressedRecipientAttachedTokenNoAad, { jsonWebKey });
    }).resolves.not.toThrow();

    expect(jsonWebEncryption.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jsonWebEncryption.header.parameters).toStrictEqual(algEncZipJkuKidHeader);

    expect(jsonWebEncryption.protectedHeader).toBeUndefined();
    expect(jsonWebEncryption.unprotectedHeader).toBeUndefined();
    expect(jsonWebEncryption.recipientUnprotectedHeader).toStrictEqual(algEncZipJkuKidHeader);

    expect(jsonWebEncryption.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from a Compressed Protected and Unprotected Attached Token with no Additional Authenticated Data.', async () => {
    let jsonWebEncryption!: FlattenedJsonWebEncryption;

    await expect(
      async () =>
        (jsonWebEncryption = await deserialize(compressedProtectedAndUnprotectedAttachedTokenNoAad, { jsonWebKey })),
    ).resolves.not.toThrow();

    expect(jsonWebEncryption.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jsonWebEncryption.header.parameters).toStrictEqual(algEncZipJkuKidHeader);

    expect(jsonWebEncryption.protectedHeader).toStrictEqual(encHeader);
    expect(jsonWebEncryption.unprotectedHeader).toStrictEqual(algZipJkuKidHeader);
    expect(jsonWebEncryption.recipientUnprotectedHeader).toBeUndefined();

    expect(jsonWebEncryption.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from a Compressed Protected and Recipient Attached Token with no Additional Authenticated Data.', async () => {
    let jsonWebEncryption!: FlattenedJsonWebEncryption;

    await expect(
      async () =>
        (jsonWebEncryption = await deserialize(compressedProtectedAndRecipientAttachedTokenNoAad, { jsonWebKey })),
    ).resolves.not.toThrow();

    expect(jsonWebEncryption.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jsonWebEncryption.header.parameters).toStrictEqual(algEncZipJkuKidHeader);

    expect(jsonWebEncryption.protectedHeader).toStrictEqual(encHeader);
    expect(jsonWebEncryption.unprotectedHeader).toBeUndefined();
    expect(jsonWebEncryption.recipientUnprotectedHeader).toStrictEqual(algZipJkuKidHeader);

    expect(jsonWebEncryption.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from a Compressed Unprotected and Recipient Attached Token with no Additional Authenticated Data.', async () => {
    let jsonWebEncryption!: FlattenedJsonWebEncryption;

    await expect(
      async () =>
        (jsonWebEncryption = await deserialize(compressedUnprotectedAndRecipientAttachedTokenNoAad, { jsonWebKey })),
    ).resolves.not.toThrow();

    expect(jsonWebEncryption.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jsonWebEncryption.header.parameters).toStrictEqual(algEncZipJkuKidHeader);

    expect(jsonWebEncryption.protectedHeader).toBeUndefined();
    expect(jsonWebEncryption.unprotectedHeader).toStrictEqual(encHeader);
    expect(jsonWebEncryption.recipientUnprotectedHeader).toStrictEqual(algZipJkuKidHeader);

    expect(jsonWebEncryption.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from a Compressed Protected, Unprotected and Recipient Attached Token with no Additional Authenticated Data.', async () => {
    let jsonWebEncryption!: FlattenedJsonWebEncryption;

    await expect(async () => {
      jsonWebEncryption = await deserialize(compressedFullAttachedTokenNoAad, { jsonWebKey });
    }).resolves.not.toThrow();

    expect(jsonWebEncryption.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jsonWebEncryption.header.parameters).toStrictEqual(algEncZipJkuKidHeader);

    expect(jsonWebEncryption.protectedHeader).toStrictEqual(encHeader);
    expect(jsonWebEncryption.unprotectedHeader).toStrictEqual(jkuHeader);
    expect(jsonWebEncryption.recipientUnprotectedHeader).toStrictEqual(algZipKidHeader);

    expect(jsonWebEncryption.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from a Compressed Protected Detached Token with no Additional Authenticated Data.', async () => {
    let jsonWebEncryption!: FlattenedJsonWebEncryption;

    await expect(async () => {
      jsonWebEncryption = await deserialize(compressedProtectedDetachedTokenNoAad, {
        jsonWebKey,
        detachedCiphertext: compressedCiphertext,
      });
    }).resolves.not.toThrow();

    expect(jsonWebEncryption.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jsonWebEncryption.header.parameters).toStrictEqual(algEncZipJkuKidHeader);

    expect(jsonWebEncryption.protectedHeader).toStrictEqual(algEncZipJkuKidHeader);
    expect(jsonWebEncryption.unprotectedHeader).toBeUndefined();
    expect(jsonWebEncryption.recipientUnprotectedHeader).toBeUndefined();

    expect(jsonWebEncryption.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from a Compressed Unprotected Detached Token with no Additional Authenticated Data.', async () => {
    let jsonWebEncryption!: FlattenedJsonWebEncryption;

    await expect(async () => {
      jsonWebEncryption = await deserialize(compressedUnprotectedDetachedTokenNoAad, {
        jsonWebKey,
        detachedCiphertext: compressedCiphertext,
      });
    }).resolves.not.toThrow();

    expect(jsonWebEncryption.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jsonWebEncryption.header.parameters).toStrictEqual(algEncZipJkuKidHeader);

    expect(jsonWebEncryption.protectedHeader).toBeUndefined();
    expect(jsonWebEncryption.unprotectedHeader).toStrictEqual(algEncZipJkuKidHeader);
    expect(jsonWebEncryption.recipientUnprotectedHeader).toBeUndefined();

    expect(jsonWebEncryption.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from a Compressed Recipient Detached Token with no Additional Authenticated Data.', async () => {
    let jsonWebEncryption!: FlattenedJsonWebEncryption;

    await expect(async () => {
      jsonWebEncryption = await deserialize(compressedRecipientDetachedTokenNoAad, {
        jsonWebKey,
        detachedCiphertext: compressedCiphertext,
      });
    }).resolves.not.toThrow();

    expect(jsonWebEncryption.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jsonWebEncryption.header.parameters).toStrictEqual(algEncZipJkuKidHeader);

    expect(jsonWebEncryption.protectedHeader).toBeUndefined();
    expect(jsonWebEncryption.unprotectedHeader).toBeUndefined();
    expect(jsonWebEncryption.recipientUnprotectedHeader).toStrictEqual(algEncZipJkuKidHeader);

    expect(jsonWebEncryption.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from a Compressed Protected and Unprotected Detached Token with no Additional Authenticated Data.', async () => {
    let jsonWebEncryption!: FlattenedJsonWebEncryption;

    await expect(async () => {
      jsonWebEncryption = await deserialize(compressedProtectedAndUnprotectedDetachedTokenNoAad, {
        jsonWebKey,
        detachedCiphertext: compressedCiphertext,
      });
    }).resolves.not.toThrow();

    expect(jsonWebEncryption.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jsonWebEncryption.header.parameters).toStrictEqual(algEncZipJkuKidHeader);

    expect(jsonWebEncryption.protectedHeader).toStrictEqual(encHeader);
    expect(jsonWebEncryption.unprotectedHeader).toStrictEqual(algZipJkuKidHeader);
    expect(jsonWebEncryption.recipientUnprotectedHeader).toBeUndefined();

    expect(jsonWebEncryption.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from a Compressed Protected and Recipient Detached Token with no Additional Authenticated Data.', async () => {
    let jsonWebEncryption!: FlattenedJsonWebEncryption;

    await expect(async () => {
      jsonWebEncryption = await deserialize(compressedProtectedAndRecipientDetachedTokenNoAad, {
        jsonWebKey,
        detachedCiphertext: compressedCiphertext,
      });
    }).resolves.not.toThrow();

    expect(jsonWebEncryption.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jsonWebEncryption.header.parameters).toStrictEqual(algEncZipJkuKidHeader);

    expect(jsonWebEncryption.protectedHeader).toStrictEqual(encHeader);
    expect(jsonWebEncryption.unprotectedHeader).toBeUndefined();
    expect(jsonWebEncryption.recipientUnprotectedHeader).toStrictEqual(algZipJkuKidHeader);

    expect(jsonWebEncryption.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from a Compressed Unprotected and Recipient Detached Token with no Additional Authenticated Data.', async () => {
    let jsonWebEncryption!: FlattenedJsonWebEncryption;

    await expect(async () => {
      jsonWebEncryption = await deserialize(compressedUnprotectedAndRecipientDetachedTokenNoAad, {
        jsonWebKey,
        detachedCiphertext: compressedCiphertext,
      });
    }).resolves.not.toThrow();

    expect(jsonWebEncryption.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jsonWebEncryption.header.parameters).toStrictEqual(algEncZipJkuKidHeader);

    expect(jsonWebEncryption.protectedHeader).toBeUndefined();
    expect(jsonWebEncryption.unprotectedHeader).toStrictEqual(encHeader);
    expect(jsonWebEncryption.recipientUnprotectedHeader).toStrictEqual(algZipJkuKidHeader);

    expect(jsonWebEncryption.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from a Compressed Protected, Unprotected and Recipient Detached Token with no Additional Authenticated Data.', async () => {
    let jsonWebEncryption!: FlattenedJsonWebEncryption;

    await expect(async () => {
      jsonWebEncryption = await deserialize(compressedFullDetachedTokenNoAad, {
        jsonWebKey,
        detachedCiphertext: compressedCiphertext,
      });
    }).resolves.not.toThrow();

    expect(jsonWebEncryption.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jsonWebEncryption.header.parameters).toStrictEqual(algEncZipJkuKidHeader);

    expect(jsonWebEncryption.protectedHeader).toStrictEqual(encHeader);
    expect(jsonWebEncryption.unprotectedHeader).toStrictEqual(jkuHeader);
    expect(jsonWebEncryption.recipientUnprotectedHeader).toStrictEqual(algZipKidHeader);

    expect(jsonWebEncryption.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from an Uncompressed Protected Attached Token with Additional Authenticated Data.', async () => {
    let jsonWebEncryption!: FlattenedJsonWebEncryption;

    await expect(async () => {
      jsonWebEncryption = await deserialize(uncompressedProtectedAttachedToken, { jsonWebKey });
    }).resolves.not.toThrow();

    expect(jsonWebEncryption.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jsonWebEncryption.header.parameters).toStrictEqual(algEncJkuKidHeader);

    expect(jsonWebEncryption.protectedHeader).toStrictEqual(algEncJkuKidHeader);
    expect(jsonWebEncryption.unprotectedHeader).toBeUndefined();
    expect(jsonWebEncryption.recipientUnprotectedHeader).toBeUndefined();

    expect(jsonWebEncryption.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from an Uncompressed Unprotected Attached Token with Additional Authenticated Data.', async () => {
    let jsonWebEncryption!: FlattenedJsonWebEncryption;

    await expect(async () => {
      jsonWebEncryption = await deserialize(uncompressedUnprotectedAttachedToken, { jsonWebKey });
    }).resolves.not.toThrow();

    expect(jsonWebEncryption.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jsonWebEncryption.header.parameters).toStrictEqual(algEncJkuKidHeader);

    expect(jsonWebEncryption.protectedHeader).toBeUndefined();
    expect(jsonWebEncryption.unprotectedHeader).toStrictEqual(algEncJkuKidHeader);
    expect(jsonWebEncryption.recipientUnprotectedHeader).toBeUndefined();

    expect(jsonWebEncryption.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from an Uncompressed Recipient Attached Token with Additional Authenticated Data.', async () => {
    let jsonWebEncryption!: FlattenedJsonWebEncryption;

    await expect(async () => {
      jsonWebEncryption = await deserialize(uncompressedRecipientAttachedToken, { jsonWebKey });
    }).resolves.not.toThrow();

    expect(jsonWebEncryption.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jsonWebEncryption.header.parameters).toStrictEqual(algEncJkuKidHeader);

    expect(jsonWebEncryption.protectedHeader).toBeUndefined();
    expect(jsonWebEncryption.unprotectedHeader).toBeUndefined();
    expect(jsonWebEncryption.recipientUnprotectedHeader).toStrictEqual(algEncJkuKidHeader);

    expect(jsonWebEncryption.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from an Uncompressed Protected and Unprotected Attached Token with Additional Authenticated Data.', async () => {
    let jsonWebEncryption!: FlattenedJsonWebEncryption;

    await expect(
      async () =>
        (jsonWebEncryption = await deserialize(uncompressedProtectedAndUnprotectedAttachedToken, { jsonWebKey })),
    ).resolves.not.toThrow();

    expect(jsonWebEncryption.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jsonWebEncryption.header.parameters).toStrictEqual(algEncJkuKidHeader);

    expect(jsonWebEncryption.protectedHeader).toStrictEqual(encHeader);
    expect(jsonWebEncryption.unprotectedHeader).toStrictEqual(algJkuKidHeader);
    expect(jsonWebEncryption.recipientUnprotectedHeader).toBeUndefined();

    expect(jsonWebEncryption.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from an Uncompressed Protected and Recipient Attached Token with Additional Authenticated Data.', async () => {
    let jsonWebEncryption!: FlattenedJsonWebEncryption;

    await expect(
      async () =>
        (jsonWebEncryption = await deserialize(uncompressedProtectedAndRecipientAttachedToken, { jsonWebKey })),
    ).resolves.not.toThrow();

    expect(jsonWebEncryption.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jsonWebEncryption.header.parameters).toStrictEqual(algEncJkuKidHeader);

    expect(jsonWebEncryption.protectedHeader).toStrictEqual(encHeader);
    expect(jsonWebEncryption.unprotectedHeader).toBeUndefined();
    expect(jsonWebEncryption.recipientUnprotectedHeader).toStrictEqual(algJkuKidHeader);

    expect(jsonWebEncryption.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from an Uncompressed Unprotected and Recipient Attached Token with Additional Authenticated Data.', async () => {
    let jsonWebEncryption!: FlattenedJsonWebEncryption;

    await expect(
      async () =>
        (jsonWebEncryption = await deserialize(uncompressedUnprotectedAndRecipientAttachedToken, { jsonWebKey })),
    ).resolves.not.toThrow();

    expect(jsonWebEncryption.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jsonWebEncryption.header.parameters).toStrictEqual(algEncJkuKidHeader);

    expect(jsonWebEncryption.protectedHeader).toBeUndefined();
    expect(jsonWebEncryption.unprotectedHeader).toStrictEqual(encHeader);
    expect(jsonWebEncryption.recipientUnprotectedHeader).toStrictEqual(algJkuKidHeader);

    expect(jsonWebEncryption.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from an Uncompressed Protected, Unprotected and Recipient Attached Token with Additional Authenticated Data.', async () => {
    let jsonWebEncryption!: FlattenedJsonWebEncryption;

    await expect(async () => {
      jsonWebEncryption = await deserialize(uncompressedFullAttachedToken, { jsonWebKey });
    }).resolves.not.toThrow();

    expect(jsonWebEncryption.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jsonWebEncryption.header.parameters).toStrictEqual(algEncJkuKidHeader);

    expect(jsonWebEncryption.protectedHeader).toStrictEqual(encHeader);
    expect(jsonWebEncryption.unprotectedHeader).toStrictEqual(jkuHeader);
    expect(jsonWebEncryption.recipientUnprotectedHeader).toStrictEqual(algKidHeader);

    expect(jsonWebEncryption.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from an Uncompressed Protected Detached Token with Additional Authenticated Data.', async () => {
    let jsonWebEncryption!: FlattenedJsonWebEncryption;

    await expect(async () => {
      jsonWebEncryption = await deserialize(uncompressedProtectedDetachedToken, {
        jsonWebKey,
        detachedCiphertext: ciphertext,
      });
    }).resolves.not.toThrow();

    expect(jsonWebEncryption.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jsonWebEncryption.header.parameters).toStrictEqual(algEncJkuKidHeader);

    expect(jsonWebEncryption.protectedHeader).toStrictEqual(algEncJkuKidHeader);
    expect(jsonWebEncryption.unprotectedHeader).toBeUndefined();
    expect(jsonWebEncryption.recipientUnprotectedHeader).toBeUndefined();

    expect(jsonWebEncryption.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from an Uncompressed Unprotected Detached Token with Additional Authenticated Data.', async () => {
    let jsonWebEncryption!: FlattenedJsonWebEncryption;

    await expect(async () => {
      jsonWebEncryption = await deserialize(uncompressedUnprotectedDetachedToken, {
        jsonWebKey,
        detachedCiphertext: ciphertext,
      });
    }).resolves.not.toThrow();

    expect(jsonWebEncryption.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jsonWebEncryption.header.parameters).toStrictEqual(algEncJkuKidHeader);

    expect(jsonWebEncryption.protectedHeader).toBeUndefined();
    expect(jsonWebEncryption.unprotectedHeader).toStrictEqual(algEncJkuKidHeader);
    expect(jsonWebEncryption.recipientUnprotectedHeader).toBeUndefined();

    expect(jsonWebEncryption.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from an Uncompressed Recipient Detached Token with Additional Authenticated Data.', async () => {
    let jsonWebEncryption!: FlattenedJsonWebEncryption;

    await expect(async () => {
      jsonWebEncryption = await deserialize(uncompressedRecipientDetachedToken, {
        jsonWebKey,
        detachedCiphertext: ciphertext,
      });
    }).resolves.not.toThrow();

    expect(jsonWebEncryption.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jsonWebEncryption.header.parameters).toStrictEqual(algEncJkuKidHeader);

    expect(jsonWebEncryption.protectedHeader).toBeUndefined();
    expect(jsonWebEncryption.unprotectedHeader).toBeUndefined();
    expect(jsonWebEncryption.recipientUnprotectedHeader).toStrictEqual(algEncJkuKidHeader);

    expect(jsonWebEncryption.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from an Uncompressed Protected and Unprotected Detached Token with Additional Authenticated Data.', async () => {
    let jsonWebEncryption!: FlattenedJsonWebEncryption;

    await expect(async () => {
      jsonWebEncryption = await deserialize(uncompressedProtectedAndUnprotectedDetachedToken, {
        jsonWebKey,
        detachedCiphertext: ciphertext,
      });
    }).resolves.not.toThrow();

    expect(jsonWebEncryption.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jsonWebEncryption.header.parameters).toStrictEqual(algEncJkuKidHeader);

    expect(jsonWebEncryption.protectedHeader).toStrictEqual(encHeader);
    expect(jsonWebEncryption.unprotectedHeader).toStrictEqual(algJkuKidHeader);
    expect(jsonWebEncryption.recipientUnprotectedHeader).toBeUndefined();

    expect(jsonWebEncryption.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from an Uncompressed Protected and Recipient Detached Token with Additional Authenticated Data.', async () => {
    let jsonWebEncryption!: FlattenedJsonWebEncryption;

    await expect(async () => {
      jsonWebEncryption = await deserialize(uncompressedProtectedAndRecipientDetachedToken, {
        jsonWebKey,
        detachedCiphertext: ciphertext,
      });
    }).resolves.not.toThrow();

    expect(jsonWebEncryption.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jsonWebEncryption.header.parameters).toStrictEqual(algEncJkuKidHeader);

    expect(jsonWebEncryption.protectedHeader).toStrictEqual(encHeader);
    expect(jsonWebEncryption.unprotectedHeader).toBeUndefined();
    expect(jsonWebEncryption.recipientUnprotectedHeader).toStrictEqual(algJkuKidHeader);

    expect(jsonWebEncryption.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from an Uncompressed Unprotected and Recipient Detached Token with Additional Authenticated Data.', async () => {
    let jsonWebEncryption!: FlattenedJsonWebEncryption;

    await expect(async () => {
      jsonWebEncryption = await deserialize(uncompressedUnprotectedAndRecipientDetachedToken, {
        jsonWebKey,
        detachedCiphertext: ciphertext,
      });
    }).resolves.not.toThrow();

    expect(jsonWebEncryption.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jsonWebEncryption.header.parameters).toStrictEqual(algEncJkuKidHeader);

    expect(jsonWebEncryption.protectedHeader).toBeUndefined();
    expect(jsonWebEncryption.unprotectedHeader).toStrictEqual(encHeader);
    expect(jsonWebEncryption.recipientUnprotectedHeader).toStrictEqual(algJkuKidHeader);

    expect(jsonWebEncryption.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from an Uncompressed Protected, Unprotected and Recipient Detached Token with Additional Authenticated Data.', async () => {
    let jsonWebEncryption!: FlattenedJsonWebEncryption;

    await expect(
      async () =>
        (jsonWebEncryption = await deserialize(uncompressedFullDetachedToken, {
          jsonWebKey,
          detachedCiphertext: ciphertext,
        })),
    ).resolves.not.toThrow();

    expect(jsonWebEncryption.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jsonWebEncryption.header.parameters).toStrictEqual(algEncJkuKidHeader);

    expect(jsonWebEncryption.protectedHeader).toStrictEqual(encHeader);
    expect(jsonWebEncryption.unprotectedHeader).toStrictEqual(jkuHeader);
    expect(jsonWebEncryption.recipientUnprotectedHeader).toStrictEqual(algKidHeader);

    expect(jsonWebEncryption.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from a Compressed Protected Attached Token with Additional Authenticated Data.', async () => {
    let jsonWebEncryption!: FlattenedJsonWebEncryption;

    await expect(async () => {
      jsonWebEncryption = await deserialize(compressedProtectedAttachedToken, { jsonWebKey });
    }).resolves.not.toThrow();

    expect(jsonWebEncryption.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jsonWebEncryption.header.parameters).toStrictEqual(algEncZipJkuKidHeader);

    expect(jsonWebEncryption.protectedHeader).toStrictEqual(algEncZipJkuKidHeader);
    expect(jsonWebEncryption.unprotectedHeader).toBeUndefined();
    expect(jsonWebEncryption.recipientUnprotectedHeader).toBeUndefined();

    expect(jsonWebEncryption.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from a Compressed Unprotected Attached Token with Additional Authenticated Data.', async () => {
    let jsonWebEncryption!: FlattenedJsonWebEncryption;

    await expect(async () => {
      jsonWebEncryption = await deserialize(compressedUnprotectedAttachedToken, { jsonWebKey });
    }).resolves.not.toThrow();

    expect(jsonWebEncryption.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jsonWebEncryption.header.parameters).toStrictEqual(algEncZipJkuKidHeader);

    expect(jsonWebEncryption.protectedHeader).toBeUndefined();
    expect(jsonWebEncryption.unprotectedHeader).toStrictEqual(algEncZipJkuKidHeader);
    expect(jsonWebEncryption.recipientUnprotectedHeader).toBeUndefined();

    expect(jsonWebEncryption.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from a Compressed Recipient Attached Token with Additional Authenticated Data.', async () => {
    let jsonWebEncryption!: FlattenedJsonWebEncryption;

    await expect(async () => {
      jsonWebEncryption = await deserialize(compressedRecipientAttachedToken, { jsonWebKey });
    }).resolves.not.toThrow();

    expect(jsonWebEncryption.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jsonWebEncryption.header.parameters).toStrictEqual(algEncZipJkuKidHeader);

    expect(jsonWebEncryption.protectedHeader).toBeUndefined();
    expect(jsonWebEncryption.unprotectedHeader).toBeUndefined();
    expect(jsonWebEncryption.recipientUnprotectedHeader).toStrictEqual(algEncZipJkuKidHeader);

    expect(jsonWebEncryption.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from a Compressed Protected and Unprotected Attached Token with Additional Authenticated Data.', async () => {
    let jsonWebEncryption!: FlattenedJsonWebEncryption;

    await expect(
      async () =>
        (jsonWebEncryption = await deserialize(compressedProtectedAndUnprotectedAttachedToken, { jsonWebKey })),
    ).resolves.not.toThrow();

    expect(jsonWebEncryption.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jsonWebEncryption.header.parameters).toStrictEqual(algEncZipJkuKidHeader);

    expect(jsonWebEncryption.protectedHeader).toStrictEqual(encHeader);
    expect(jsonWebEncryption.unprotectedHeader).toStrictEqual(algZipJkuKidHeader);
    expect(jsonWebEncryption.recipientUnprotectedHeader).toBeUndefined();

    expect(jsonWebEncryption.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from a Compressed Protected and Recipient Attached Token with Additional Authenticated Data.', async () => {
    let jsonWebEncryption!: FlattenedJsonWebEncryption;

    await expect(async () => {
      jsonWebEncryption = await deserialize(compressedProtectedAndRecipientAttachedToken, { jsonWebKey });
    }).resolves.not.toThrow();

    expect(jsonWebEncryption.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jsonWebEncryption.header.parameters).toStrictEqual(algEncZipJkuKidHeader);

    expect(jsonWebEncryption.protectedHeader).toStrictEqual(encHeader);
    expect(jsonWebEncryption.unprotectedHeader).toBeUndefined();
    expect(jsonWebEncryption.recipientUnprotectedHeader).toStrictEqual(algZipJkuKidHeader);

    expect(jsonWebEncryption.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from a Compressed Unprotected and Recipient Attached Token with Additional Authenticated Data.', async () => {
    let jsonWebEncryption!: FlattenedJsonWebEncryption;

    await expect(
      async () =>
        (jsonWebEncryption = await deserialize(compressedUnprotectedAndRecipientAttachedToken, { jsonWebKey })),
    ).resolves.not.toThrow();

    expect(jsonWebEncryption.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jsonWebEncryption.header.parameters).toStrictEqual(algEncZipJkuKidHeader);

    expect(jsonWebEncryption.protectedHeader).toBeUndefined();
    expect(jsonWebEncryption.unprotectedHeader).toStrictEqual(encHeader);
    expect(jsonWebEncryption.recipientUnprotectedHeader).toStrictEqual(algZipJkuKidHeader);

    expect(jsonWebEncryption.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from a Compressed Protected, Unprotected and Recipient Attached Token with Additional Authenticated Data.', async () => {
    let jsonWebEncryption!: FlattenedJsonWebEncryption;

    await expect(async () => {
      jsonWebEncryption = await deserialize(compressedFullAttachedToken, { jsonWebKey });
    }).resolves.not.toThrow();

    expect(jsonWebEncryption.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jsonWebEncryption.header.parameters).toStrictEqual(algEncZipJkuKidHeader);

    expect(jsonWebEncryption.protectedHeader).toStrictEqual(encHeader);
    expect(jsonWebEncryption.unprotectedHeader).toStrictEqual(jkuHeader);
    expect(jsonWebEncryption.recipientUnprotectedHeader).toStrictEqual(algZipKidHeader);

    expect(jsonWebEncryption.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from a Compressed Protected Detached Token with Additional Authenticated Data.', async () => {
    let jsonWebEncryption!: FlattenedJsonWebEncryption;

    await expect(async () => {
      jsonWebEncryption = await deserialize(compressedProtectedDetachedToken, {
        jsonWebKey,
        detachedCiphertext: compressedCiphertext,
      });
    }).resolves.not.toThrow();

    expect(jsonWebEncryption.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jsonWebEncryption.header.parameters).toStrictEqual(algEncZipJkuKidHeader);

    expect(jsonWebEncryption.protectedHeader).toStrictEqual(algEncZipJkuKidHeader);
    expect(jsonWebEncryption.unprotectedHeader).toBeUndefined();
    expect(jsonWebEncryption.recipientUnprotectedHeader).toBeUndefined();

    expect(jsonWebEncryption.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from a Compressed Unprotected Detached Token with Additional Authenticated Data.', async () => {
    let jsonWebEncryption!: FlattenedJsonWebEncryption;

    await expect(async () => {
      jsonWebEncryption = await deserialize(compressedUnprotectedDetachedToken, {
        jsonWebKey,
        detachedCiphertext: compressedCiphertext,
      });
    }).resolves.not.toThrow();

    expect(jsonWebEncryption.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jsonWebEncryption.header.parameters).toStrictEqual(algEncZipJkuKidHeader);

    expect(jsonWebEncryption.protectedHeader).toBeUndefined();
    expect(jsonWebEncryption.unprotectedHeader).toStrictEqual(algEncZipJkuKidHeader);
    expect(jsonWebEncryption.recipientUnprotectedHeader).toBeUndefined();

    expect(jsonWebEncryption.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from a Compressed Recipient Detached Token with Additional Authenticated Data.', async () => {
    let jsonWebEncryption!: FlattenedJsonWebEncryption;

    await expect(async () => {
      jsonWebEncryption = await deserialize(compressedRecipientDetachedToken, {
        jsonWebKey,
        detachedCiphertext: compressedCiphertext,
      });
    }).resolves.not.toThrow();

    expect(jsonWebEncryption.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jsonWebEncryption.header.parameters).toStrictEqual(algEncZipJkuKidHeader);

    expect(jsonWebEncryption.protectedHeader).toBeUndefined();
    expect(jsonWebEncryption.unprotectedHeader).toBeUndefined();
    expect(jsonWebEncryption.recipientUnprotectedHeader).toStrictEqual(algEncZipJkuKidHeader);

    expect(jsonWebEncryption.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from a Compressed Protected and Unprotected Detached Token with Additional Authenticated Data.', async () => {
    let jsonWebEncryption!: FlattenedJsonWebEncryption;

    await expect(async () => {
      jsonWebEncryption = await deserialize(compressedProtectedAndUnprotectedDetachedToken, {
        jsonWebKey,
        detachedCiphertext: compressedCiphertext,
      });
    }).resolves.not.toThrow();

    expect(jsonWebEncryption.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jsonWebEncryption.header.parameters).toStrictEqual(algEncZipJkuKidHeader);

    expect(jsonWebEncryption.protectedHeader).toStrictEqual(encHeader);
    expect(jsonWebEncryption.unprotectedHeader).toStrictEqual(algZipJkuKidHeader);
    expect(jsonWebEncryption.recipientUnprotectedHeader).toBeUndefined();

    expect(jsonWebEncryption.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from a Compressed Protected and Recipient Detached Token with Additional Authenticated Data.', async () => {
    let jsonWebEncryption!: FlattenedJsonWebEncryption;

    await expect(async () => {
      jsonWebEncryption = await deserialize(compressedProtectedAndRecipientDetachedToken, {
        jsonWebKey,
        detachedCiphertext: compressedCiphertext,
      });
    }).resolves.not.toThrow();

    expect(jsonWebEncryption.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jsonWebEncryption.header.parameters).toStrictEqual(algEncZipJkuKidHeader);

    expect(jsonWebEncryption.protectedHeader).toStrictEqual(encHeader);
    expect(jsonWebEncryption.unprotectedHeader).toBeUndefined();
    expect(jsonWebEncryption.recipientUnprotectedHeader).toStrictEqual(algZipJkuKidHeader);

    expect(jsonWebEncryption.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from a Compressed Unprotected and Recipient Detached Token with Additional Authenticated Data.', async () => {
    let jsonWebEncryption!: FlattenedJsonWebEncryption;

    await expect(async () => {
      jsonWebEncryption = await deserialize(compressedUnprotectedAndRecipientDetachedToken, {
        jsonWebKey,
        detachedCiphertext: compressedCiphertext,
      });
    }).resolves.not.toThrow();

    expect(jsonWebEncryption.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jsonWebEncryption.header.parameters).toStrictEqual(algEncZipJkuKidHeader);

    expect(jsonWebEncryption.protectedHeader).toBeUndefined();
    expect(jsonWebEncryption.unprotectedHeader).toStrictEqual(encHeader);
    expect(jsonWebEncryption.recipientUnprotectedHeader).toStrictEqual(algZipJkuKidHeader);

    expect(jsonWebEncryption.plaintext).toStrictEqual(plaintext);
  });

  it('should return the deserialized Flattened JSON Web Encryption from a Compressed Protected, Unprotected and Recipient Detached Token with Additional Authenticated Data.', async () => {
    let jsonWebEncryption!: FlattenedJsonWebEncryption;

    await expect(async () => {
      jsonWebEncryption = await deserialize(compressedFullDetachedToken, {
        jsonWebKey,
        detachedCiphertext: compressedCiphertext,
      });
    }).resolves.not.toThrow();

    expect(jsonWebEncryption.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jsonWebEncryption.header.parameters).toStrictEqual(algEncZipJkuKidHeader);

    expect(jsonWebEncryption.protectedHeader).toStrictEqual(encHeader);
    expect(jsonWebEncryption.unprotectedHeader).toStrictEqual(jkuHeader);
    expect(jsonWebEncryption.recipientUnprotectedHeader).toStrictEqual(algZipKidHeader);

    expect(jsonWebEncryption.plaintext).toStrictEqual(plaintext);
  });
});
