import { Buffer } from 'buffer';
import https from 'https';
import { Stream } from 'stream';

import { jsonStringify } from '@guarani/primitives';

import { InvalidJsonWebEncryptionError } from '../../../errors/invalid-jsonwebencryption.error';
import { OctetSequenceJsonWebKey } from '../../../jwa/jwk/oct/octet-sequence.jsonwebkey';
import { JsonWebEncryptionHeader } from '../../jsonwebencryption-header';
import { JsonWebEncryptionHeaderParameters } from '../../jsonwebencryption-header.parameters';
import { deserialize } from './deserialize';
import { GeneralJsonWebEncryption } from './general-jsonwebencryption';
import { GeneralJsonWebEncryptionToken } from './general-jsonwebencryption.token';

const invalidTokens: any[] = [undefined, null, true, 1, 1.2, 1n, '', Symbol('a'), Buffer, Buffer.alloc(1), () => 1, []];

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

const invalidRecipients: any[] = [
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
  [[]],
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

describe('deserialize()', () => {
  const wrongEkToken: GeneralJsonWebEncryptionToken = {
    protected: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    unprotected: { jku: 'https://server.example.com/keys.jwks' },
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    aad: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    ciphertext: 'KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY',
    tag: 'U0m_YmjN04DJvceFICbCVQ',
    recipients: [
      { header: { alg: 'A128KW', kid: '7' }, encrypted_key: 'anBl9PSuJobKWwzWzJCqfMnejCvM5-WadN3zXMGyoCLW8_xmUldY3Q' },
    ],
  };

  const wrongIvToken: GeneralJsonWebEncryptionToken = {
    protected: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    unprotected: { jku: 'https://server.example.com/keys.jwks' },
    iv: 'eE63cGwX4T7eSspUA72t2Q',
    aad: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    ciphertext: 'KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY',
    tag: 'U0m_YmjN04DJvceFICbCVQ',
    recipients: [
      { header: { alg: 'A128KW', kid: '7' }, encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ' },
    ],
  };

  const wrongAadToken: GeneralJsonWebEncryptionToken = {
    protected: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    unprotected: { jku: 'https://server.example.com/keys.jwks' },
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    aad: 'eyJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0',
    ciphertext: 'KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY',
    tag: 'U0m_YmjN04DJvceFICbCVQ',
    recipients: [
      { header: { alg: 'A128KW', kid: '7' }, encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ' },
    ],
  };

  const wrongCiphertextToken: GeneralJsonWebEncryptionToken = {
    protected: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    unprotected: { jku: 'https://server.example.com/keys.jwks' },
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    aad: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    ciphertext: 'giYkZlt454236QV7AdREOuT0UOQrnNW1dpTna5JQpDk',
    tag: 'U0m_YmjN04DJvceFICbCVQ',
    recipients: [
      { header: { alg: 'A128KW', kid: '7' }, encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ' },
    ],
  };

  const wrongTagToken: GeneralJsonWebEncryptionToken = {
    protected: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    unprotected: { jku: 'https://server.example.com/keys.jwks' },
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    aad: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    ciphertext: 'KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY',
    tag: '24tpOFXtrTHSIdllxDRtlw',
    recipients: [
      { header: { alg: 'A128KW', kid: '7' }, encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ' },
    ],
  };

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

  it.each(invalidTokens)(
    'should throw when the provided General JSON Web Encryption Token is invalid.',
    async (token) => {
      await expect(deserialize(token)).rejects.toThrowWithMessage(
        TypeError,
        'The provided General JSON Web Encryption Token is invalid.',
      );
    },
  );

  it.each(invalidDeserializeOptions)('should throw when the provided options is invalid.', async (options) => {
    await expect(deserialize(uncompressedProtectedAttachedTokenNoAad, options)).rejects.toThrowWithMessage(
      TypeError,
      'The provided options is invalid.',
    );
  });

  it.each(invalidDetachedCiphertexts)(
    'should throw when the provided option "detachedCiphertext" is invalid.',
    async (detachedCiphertext) => {
      await expect(
        deserialize(uncompressedProtectedAttachedTokenNoAad, { detachedCiphertext }),
      ).rejects.toThrowWithMessage(TypeError, 'The provided option "detachedCiphertext" is invalid.');
    },
  );

  it.each(invalidRecipients)('should throw when the provided option "recipients" is invalid.', async (recipients) => {
    await expect(deserialize(uncompressedProtectedAttachedTokenNoAad, { recipients })).rejects.toThrowWithMessage(
      TypeError,
      'The provided option "recipients" is invalid.',
    );
  });

  it.each(invalidJwks)('should throw when the provided recipient option "jwk" is invalid.', async (jwk) => {
    await expect(
      deserialize(uncompressedProtectedAttachedTokenNoAad, { recipients: [{ jwk }] }),
    ).rejects.toThrowWithMessage(TypeError, 'The provided recipient option "jwk" is invalid.');
  });

  it.each(invalidExpectedAlgorithms)(
    'should throw when the provided recipient option "expectedKeyManagementAlgorithms" is invalid.',
    async (expectedKeyManagementAlgorithms) => {
      await expect(
        deserialize(uncompressedProtectedAttachedTokenNoAad, {
          recipients: [{ expectedKeyManagementAlgorithms }],
        }),
      ).rejects.toThrowWithMessage(
        TypeError,
        'The provided recipient option "expectedKeyManagementAlgorithms" is invalid.',
      );
    },
  );

  it.each(invalidExpectedAlgorithms)(
    'should throw when the provided recipient option "expectedContentEncryptionAlgorithms" is invalid.',
    async (expectedContentEncryptionAlgorithms) => {
      await expect(
        deserialize(uncompressedProtectedAttachedTokenNoAad, {
          recipients: [{ expectedContentEncryptionAlgorithms }],
        }),
      ).rejects.toThrowWithMessage(
        TypeError,
        'The provided recipient option "expectedContentEncryptionAlgorithms" is invalid.',
      );
    },
  );

  it.each(invalidExpectedAlgorithms)(
    'should throw when the provided recipient option "expectedCompressionAlgorithms" is invalid.',
    async (expectedCompressionAlgorithms) => {
      await expect(
        deserialize(uncompressedProtectedAttachedTokenNoAad, {
          recipients: [{ expectedCompressionAlgorithms }],
        }),
      ).rejects.toThrowWithMessage(
        TypeError,
        'The provided recipient option "expectedCompressionAlgorithms" is invalid.',
      );
    },
  );

  it('should throw when the option "recipients" has length different than the recipients of the provided General JSON Web Encryption Token.', async () => {
    await expect(
      deserialize(uncompressedProtectedAttachedTokenNoAad, {
        recipients: [{ jwk }, { jwk }],
      }),
    ).rejects.toThrowWithMessage(
      TypeError,
      'The length of the option "recipients" and the General JSON Web Encryption Token Recipients do not match.',
    );
  });

  it('should throw when deserializing a Detached General JSON Web Encryption Token and not providing a Detached Ciphertext.', async () => {
    await expect(deserialize(uncompressedProtectedDetachedTokenNoAad)).rejects.toThrowWithMessage(
      InvalidJsonWebEncryptionError,
      'The JSON Web Encryption requires a valid Ciphertext.',
    );
  });

  it('should throw when providing a Detached Ciphertext for a General JSON Web Encryption Token that already has a Ciphertext.', async () => {
    await expect(
      deserialize(uncompressedProtectedAttachedTokenNoAad, {
        detachedCiphertext: ciphertext,
      }),
    ).rejects.toThrowWithMessage(
      InvalidJsonWebEncryptionError,
      'The provided JSON Web Encryption already has a defined Ciphertext.',
    );
  });

  it('should throw when the JSON Web Encryption Key Management Algorithm of the General JSON Web Encryption Token is unexpected.', async () => {
    await expect(
      deserialize(uncompressedProtectedAttachedTokenNoAad, {
        recipients: [{ expectedKeyManagementAlgorithms: ['A256KW'] }],
      }),
    ).rejects.toThrowWithMessage(
      InvalidJsonWebEncryptionError,
      'Unexpected JSON Web Encryption Key Management Algorithm "A128KW".',
    );
  });

  it('should throw when the JSON Web Encryption Content Encryption Algorithm of the General JSON Web Encryption Token is unexpected.', async () => {
    await expect(
      deserialize(uncompressedProtectedAttachedTokenNoAad, {
        recipients: [{ expectedContentEncryptionAlgorithms: ['A256CBC-HS512'] }],
      }),
    ).rejects.toThrowWithMessage(
      InvalidJsonWebEncryptionError,
      'Unexpected JSON Web Encryption Content Encryption Algorithm "A128CBC-HS256".',
    );
  });

  it('should throw when the JSON Web Encryption Compression Algorithm of the General JSON Web Encryption Token is unexpected.', async () => {
    await expect(
      deserialize(uncompressedProtectedAttachedTokenNoAad, {
        recipients: [{ expectedCompressionAlgorithms: ['DEF'] }],
      }),
    ).rejects.toThrowWithMessage(
      InvalidJsonWebEncryptionError,
      'Unexpected JSON Web Encryption Compression Algorithm "".',
    );
  });

  it('should throw when the provided Encrypted Key fails to deserialize the provided General JSON Web Encryption Token.', async () => {
    await expect(deserialize(wrongEkToken)).rejects.toThrow();
  });

  it('should throw when the provided Initialization Vector fails to deserialize the provided General JSON Web Encryption Token.', async () => {
    await expect(deserialize(wrongIvToken)).rejects.toThrow();
  });

  it('should throw when the provided Additional Authenticated Data fails to deserialize the provided General JSON Web Encryption Token.', async () => {
    await expect(deserialize(wrongAadToken)).rejects.toThrow();
  });

  it('should throw when the provided Ciphertext fails to deserialize the provided General JSON Web Encryption Token.', async () => {
    await expect(deserialize(wrongCiphertextToken)).rejects.toThrow();
  });

  it('should throw when the provided Authentication Tag fails to deserialize the provided General JSON Web Encryption Token.', async () => {
    await expect(deserialize(wrongTagToken)).rejects.toThrow();
  });

  it('should return the deserialized General JSON Web Encryption from an Uncompressed Protected Attached Token with no Additional Authenticated Data.', async () => {
    let jwe!: GeneralJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(uncompressedProtectedAttachedTokenNoAad, { recipients: [{ jwk }] });
    }).resolves.not.toThrow();

    expect(jwe.plaintext).toStrictEqual(plaintext);

    expect(jwe.recipients).toBeArrayOfSize(1);

    expect(jwe.recipients[0]!.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.recipients[0]!.header.parameters).toStrictEqual(algEncJkuKidHeader);
    expect(jwe.recipients[0]!.recipientUnprotectedHeader).toBeUndefined();

    expect(jwe.protectedHeader).toStrictEqual(algEncJkuKidHeader);
    expect(jwe.unprotectedHeader).toBeUndefined();
  });

  it('should return the deserialized General JSON Web Encryption from an Uncompressed Unprotected Attached Token with no Additional Authenticated Data.', async () => {
    let jwe!: GeneralJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(uncompressedUnprotectedAttachedTokenNoAad, { recipients: [{ jwk }] });
    }).resolves.not.toThrow();

    expect(jwe.plaintext).toStrictEqual(plaintext);

    expect(jwe.recipients).toBeArrayOfSize(1);

    expect(jwe.recipients[0]!.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.recipients[0]!.header.parameters).toStrictEqual(algEncJkuKidHeader);
    expect(jwe.recipients[0]!.recipientUnprotectedHeader).toBeUndefined();

    expect(jwe.protectedHeader).toBeUndefined();
    expect(jwe.unprotectedHeader).toStrictEqual(algEncJkuKidHeader);
  });

  it('should return the deserialized General JSON Web Encryption from an Uncompressed Recipient Attached Token with no Additional Authenticated Data.', async () => {
    let jwe!: GeneralJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(uncompressedRecipientAttachedTokenNoAad, { recipients: [{ jwk }] });
    }).resolves.not.toThrow();

    expect(jwe.plaintext).toStrictEqual(plaintext);

    expect(jwe.recipients).toBeArrayOfSize(1);

    expect(jwe.recipients[0]!.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.recipients[0]!.header.parameters).toStrictEqual(algEncJkuKidHeader);
    expect(jwe.recipients[0]!.recipientUnprotectedHeader).toStrictEqual(algEncJkuKidHeader);

    expect(jwe.protectedHeader).toBeUndefined();
    expect(jwe.unprotectedHeader).toBeUndefined();
  });

  it('should return the deserialized General JSON Web Encryption from an Uncompressed Protected and Unprotected Attached Token with no Additional Authenticated Data.', async () => {
    let jwe!: GeneralJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(uncompressedProtectedAndUnprotectedAttachedTokenNoAad, { recipients: [{ jwk }] });
    }).resolves.not.toThrow();

    expect(jwe.plaintext).toStrictEqual(plaintext);

    expect(jwe.recipients).toBeArrayOfSize(1);

    expect(jwe.recipients[0]!.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.recipients[0]!.header.parameters).toStrictEqual(algEncJkuKidHeader);
    expect(jwe.recipients[0]!.recipientUnprotectedHeader).toBeUndefined();

    expect(jwe.protectedHeader).toStrictEqual(encHeader);
    expect(jwe.unprotectedHeader).toStrictEqual(algJkuKidHeader);
  });

  it('should return the deserialized General JSON Web Encryption from an Uncompressed Protected and Recipient Attached Token with no Additional Authenticated Data.', async () => {
    let jwe!: GeneralJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(uncompressedProtectedAndRecipientAttachedTokenNoAad, { recipients: [{ jwk }] });
    }).resolves.not.toThrow();

    expect(jwe.plaintext).toStrictEqual(plaintext);

    expect(jwe.recipients).toBeArrayOfSize(1);

    expect(jwe.recipients[0]!.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.recipients[0]!.header.parameters).toStrictEqual(algEncJkuKidHeader);
    expect(jwe.recipients[0]!.recipientUnprotectedHeader).toStrictEqual(algJkuKidHeader);

    expect(jwe.protectedHeader).toStrictEqual(encHeader);
    expect(jwe.unprotectedHeader).toBeUndefined();
  });

  it('should return the deserialized General JSON Web Encryption from an Uncompressed Unprotected and Recipient Attached Token with no Additional Authenticated Data.', async () => {
    let jwe!: GeneralJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(uncompressedUnprotectedAndRecipientAttachedTokenNoAad, { recipients: [{ jwk }] });
    }).resolves.not.toThrow();

    expect(jwe.plaintext).toStrictEqual(plaintext);

    expect(jwe.recipients).toBeArrayOfSize(1);

    expect(jwe.recipients[0]!.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.recipients[0]!.header.parameters).toStrictEqual(algEncJkuKidHeader);
    expect(jwe.recipients[0]!.recipientUnprotectedHeader).toStrictEqual(algJkuKidHeader);

    expect(jwe.protectedHeader).toBeUndefined();
    expect(jwe.unprotectedHeader).toStrictEqual(encHeader);
  });

  it('should return the deserialized General JSON Web Encryption from an Uncompressed Protected, Unprotected and Recipient Attached Token with no Additional Authenticated Data.', async () => {
    let jwe!: GeneralJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(uncompressedFullAttachedTokenNoAad, { recipients: [{ jwk }] });
    }).resolves.not.toThrow();

    expect(jwe.plaintext).toStrictEqual(plaintext);

    expect(jwe.recipients).toBeArrayOfSize(1);

    expect(jwe.recipients[0]!.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.recipients[0]!.header.parameters).toStrictEqual(algEncJkuKidHeader);
    expect(jwe.recipients[0]!.recipientUnprotectedHeader).toStrictEqual(algKidHeader);

    expect(jwe.protectedHeader).toStrictEqual(encHeader);
    expect(jwe.unprotectedHeader).toStrictEqual(jkuHeader);
  });

  it('should return the deserialized General JSON Web Encryption from an Uncompressed Protected Detached Token with no Additional Authenticated Data.', async () => {
    let jwe!: GeneralJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(uncompressedProtectedDetachedTokenNoAad, {
        detachedCiphertext: ciphertext,
        recipients: [{ jwk }],
      });
    }).resolves.not.toThrow();

    expect(jwe.plaintext).toStrictEqual(plaintext);

    expect(jwe.recipients).toBeArrayOfSize(1);

    expect(jwe.recipients[0]!.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.recipients[0]!.header.parameters).toStrictEqual(algEncJkuKidHeader);
    expect(jwe.recipients[0]!.recipientUnprotectedHeader).toBeUndefined();

    expect(jwe.protectedHeader).toStrictEqual(algEncJkuKidHeader);
    expect(jwe.unprotectedHeader).toBeUndefined();
  });

  it('should return the deserialized General JSON Web Encryption from an Uncompressed Unprotected Detached Token with no Additional Authenticated Data.', async () => {
    let jwe!: GeneralJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(uncompressedUnprotectedDetachedTokenNoAad, {
        detachedCiphertext: ciphertext,
        recipients: [{ jwk }],
      });
    }).resolves.not.toThrow();

    expect(jwe.plaintext).toStrictEqual(plaintext);

    expect(jwe.recipients).toBeArrayOfSize(1);

    expect(jwe.recipients[0]!.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.recipients[0]!.header.parameters).toStrictEqual(algEncJkuKidHeader);
    expect(jwe.recipients[0]!.recipientUnprotectedHeader).toBeUndefined();

    expect(jwe.protectedHeader).toBeUndefined();
    expect(jwe.unprotectedHeader).toStrictEqual(algEncJkuKidHeader);
  });

  it('should return the deserialized General JSON Web Encryption from an Uncompressed Recipient Detached Token with no Additional Authenticated Data.', async () => {
    let jwe!: GeneralJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(uncompressedRecipientDetachedTokenNoAad, {
        detachedCiphertext: ciphertext,
        recipients: [{ jwk }],
      });
    }).resolves.not.toThrow();

    expect(jwe.plaintext).toStrictEqual(plaintext);

    expect(jwe.recipients).toBeArrayOfSize(1);

    expect(jwe.recipients[0]!.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.recipients[0]!.header.parameters).toStrictEqual(algEncJkuKidHeader);
    expect(jwe.recipients[0]!.recipientUnprotectedHeader).toStrictEqual(algEncJkuKidHeader);

    expect(jwe.protectedHeader).toBeUndefined();
    expect(jwe.unprotectedHeader).toBeUndefined();
  });

  it('should return the deserialized General JSON Web Encryption from an Uncompressed Protected and Unprotected Detached Token with no Additional Authenticated Data.', async () => {
    let jwe!: GeneralJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(uncompressedProtectedAndUnprotectedDetachedTokenNoAad, {
        detachedCiphertext: ciphertext,
        recipients: [{ jwk }],
      });
    }).resolves.not.toThrow();

    expect(jwe.plaintext).toStrictEqual(plaintext);

    expect(jwe.recipients).toBeArrayOfSize(1);

    expect(jwe.recipients[0]!.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.recipients[0]!.header.parameters).toStrictEqual(algEncJkuKidHeader);
    expect(jwe.recipients[0]!.recipientUnprotectedHeader).toBeUndefined();

    expect(jwe.protectedHeader).toStrictEqual(encHeader);
    expect(jwe.unprotectedHeader).toStrictEqual(algJkuKidHeader);
  });

  it('should return the deserialized General JSON Web Encryption from an Uncompressed Protected and Recipient Detached Token with no Additional Authenticated Data.', async () => {
    let jwe!: GeneralJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(uncompressedProtectedAndRecipientDetachedTokenNoAad, {
        detachedCiphertext: ciphertext,
        recipients: [{ jwk }],
      });
    }).resolves.not.toThrow();

    expect(jwe.plaintext).toStrictEqual(plaintext);

    expect(jwe.recipients).toBeArrayOfSize(1);

    expect(jwe.recipients[0]!.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.recipients[0]!.header.parameters).toStrictEqual(algEncJkuKidHeader);
    expect(jwe.recipients[0]!.recipientUnprotectedHeader).toStrictEqual(algJkuKidHeader);

    expect(jwe.protectedHeader).toStrictEqual(encHeader);
    expect(jwe.unprotectedHeader).toBeUndefined();
  });

  it('should return the deserialized General JSON Web Encryption from an Uncompressed Unprotected and Recipient Detached Token with no Additional Authenticated Data.', async () => {
    let jwe!: GeneralJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(uncompressedUnprotectedAndRecipientDetachedTokenNoAad, {
        detachedCiphertext: ciphertext,
        recipients: [{ jwk }],
      });
    }).resolves.not.toThrow();

    expect(jwe.plaintext).toStrictEqual(plaintext);

    expect(jwe.recipients).toBeArrayOfSize(1);

    expect(jwe.recipients[0]!.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.recipients[0]!.header.parameters).toStrictEqual(algEncJkuKidHeader);
    expect(jwe.recipients[0]!.recipientUnprotectedHeader).toStrictEqual(algJkuKidHeader);

    expect(jwe.protectedHeader).toBeUndefined();
    expect(jwe.unprotectedHeader).toStrictEqual(encHeader);
  });

  it('should return the deserialized General JSON Web Encryption from an Uncompressed Protected, Unprotected and Recipient Detached Token with no Additional Authenticated Data.', async () => {
    let jwe!: GeneralJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(uncompressedFullDetachedTokenNoAad, {
        detachedCiphertext: ciphertext,
        recipients: [{ jwk }],
      });
    }).resolves.not.toThrow();

    expect(jwe.plaintext).toStrictEqual(plaintext);

    expect(jwe.recipients).toBeArrayOfSize(1);

    expect(jwe.recipients[0]!.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.recipients[0]!.header.parameters).toStrictEqual(algEncJkuKidHeader);
    expect(jwe.recipients[0]!.recipientUnprotectedHeader).toStrictEqual(algKidHeader);

    expect(jwe.protectedHeader).toStrictEqual(encHeader);
    expect(jwe.unprotectedHeader).toStrictEqual(jkuHeader);
  });

  it('should return the deserialized General JSON Web Encryption from a Compressed Protected Attached Token with no Additional Authenticated Data.', async () => {
    let jwe!: GeneralJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(compressedProtectedAttachedTokenNoAad, { recipients: [{ jwk }] });
    }).resolves.not.toThrow();

    expect(jwe.plaintext).toStrictEqual(plaintext);

    expect(jwe.recipients).toBeArrayOfSize(1);

    expect(jwe.recipients[0]!.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.recipients[0]!.header.parameters).toStrictEqual(algEncZipJkuKidHeader);
    expect(jwe.recipients[0]!.recipientUnprotectedHeader).toBeUndefined();

    expect(jwe.protectedHeader).toStrictEqual(algEncZipJkuKidHeader);
    expect(jwe.unprotectedHeader).toBeUndefined();
  });

  it('should return the deserialized General JSON Web Encryption from a Compressed Unprotected Attached Token with no Additional Authenticated Data.', async () => {
    let jwe!: GeneralJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(compressedUnprotectedAttachedTokenNoAad, { recipients: [{ jwk }] });
    }).resolves.not.toThrow();

    expect(jwe.plaintext).toStrictEqual(plaintext);

    expect(jwe.recipients).toBeArrayOfSize(1);

    expect(jwe.recipients[0]!.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.recipients[0]!.header.parameters).toStrictEqual(algEncZipJkuKidHeader);
    expect(jwe.recipients[0]!.recipientUnprotectedHeader).toBeUndefined();

    expect(jwe.protectedHeader).toBeUndefined();
    expect(jwe.unprotectedHeader).toStrictEqual(algEncZipJkuKidHeader);
  });

  it('should return the deserialized General JSON Web Encryption from a Compressed Recipient Attached Token with no Additional Authenticated Data.', async () => {
    let jwe!: GeneralJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(compressedRecipientAttachedTokenNoAad, { recipients: [{ jwk }] });
    }).resolves.not.toThrow();

    expect(jwe.plaintext).toStrictEqual(plaintext);

    expect(jwe.recipients).toBeArrayOfSize(1);

    expect(jwe.recipients[0]!.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.recipients[0]!.header.parameters).toStrictEqual(algEncZipJkuKidHeader);
    expect(jwe.recipients[0]!.recipientUnprotectedHeader).toStrictEqual(algEncZipJkuKidHeader);

    expect(jwe.protectedHeader).toBeUndefined();
    expect(jwe.unprotectedHeader).toBeUndefined();
  });

  it('should return the deserialized General JSON Web Encryption from a Compressed Protected and Unprotected Attached Token with no Additional Authenticated Data.', async () => {
    let jwe!: GeneralJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(compressedProtectedAndUnprotectedAttachedTokenNoAad, { recipients: [{ jwk }] });
    }).resolves.not.toThrow();

    expect(jwe.plaintext).toStrictEqual(plaintext);

    expect(jwe.recipients).toBeArrayOfSize(1);

    expect(jwe.recipients[0]!.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.recipients[0]!.header.parameters).toStrictEqual(algEncZipJkuKidHeader);
    expect(jwe.recipients[0]!.recipientUnprotectedHeader).toBeUndefined();

    expect(jwe.protectedHeader).toStrictEqual(encHeader);
    expect(jwe.unprotectedHeader).toStrictEqual(algZipJkuKidHeader);
  });

  it('should return the deserialized General JSON Web Encryption from a Compressed Protected and Recipient Attached Token with no Additional Authenticated Data.', async () => {
    let jwe!: GeneralJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(compressedProtectedAndRecipientAttachedTokenNoAad, { recipients: [{ jwk }] });
    }).resolves.not.toThrow();

    expect(jwe.plaintext).toStrictEqual(plaintext);

    expect(jwe.recipients).toBeArrayOfSize(1);

    expect(jwe.recipients[0]!.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.recipients[0]!.header.parameters).toStrictEqual(algEncZipJkuKidHeader);
    expect(jwe.recipients[0]!.recipientUnprotectedHeader).toStrictEqual(algZipJkuKidHeader);

    expect(jwe.protectedHeader).toStrictEqual(encHeader);
    expect(jwe.unprotectedHeader).toBeUndefined();
  });

  it('should return the deserialized General JSON Web Encryption from a Compressed Unprotected and Recipient Attached Token with no Additional Authenticated Data.', async () => {
    let jwe!: GeneralJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(compressedUnprotectedAndRecipientAttachedTokenNoAad, { recipients: [{ jwk }] });
    }).resolves.not.toThrow();

    expect(jwe.plaintext).toStrictEqual(plaintext);

    expect(jwe.recipients).toBeArrayOfSize(1);

    expect(jwe.recipients[0]!.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.recipients[0]!.header.parameters).toStrictEqual(algEncZipJkuKidHeader);
    expect(jwe.recipients[0]!.recipientUnprotectedHeader).toStrictEqual(algZipJkuKidHeader);

    expect(jwe.protectedHeader).toBeUndefined();
    expect(jwe.unprotectedHeader).toStrictEqual(encHeader);
  });

  it('should return the deserialized General JSON Web Encryption from a Compressed Protected, Unprotected and Recipient Attached Token with no Additional Authenticated Data.', async () => {
    let jwe!: GeneralJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(compressedFullAttachedTokenNoAad, { recipients: [{ jwk }] });
    }).resolves.not.toThrow();

    expect(jwe.plaintext).toStrictEqual(plaintext);

    expect(jwe.recipients).toBeArrayOfSize(1);

    expect(jwe.recipients[0]!.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.recipients[0]!.header.parameters).toStrictEqual(algEncZipJkuKidHeader);
    expect(jwe.recipients[0]!.recipientUnprotectedHeader).toStrictEqual(algZipKidHeader);

    expect(jwe.protectedHeader).toStrictEqual(encHeader);
    expect(jwe.unprotectedHeader).toStrictEqual(jkuHeader);
  });

  it('should return the deserialized General JSON Web Encryption from a Compressed Protected Detached Token with no Additional Authenticated Data.', async () => {
    let jwe!: GeneralJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(compressedProtectedDetachedTokenNoAad, {
        detachedCiphertext: compressedCiphertext,
        recipients: [{ jwk }],
      });
    }).resolves.not.toThrow();

    expect(jwe.plaintext).toStrictEqual(plaintext);

    expect(jwe.recipients).toBeArrayOfSize(1);

    expect(jwe.recipients[0]!.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.recipients[0]!.header.parameters).toStrictEqual(algEncZipJkuKidHeader);
    expect(jwe.recipients[0]!.recipientUnprotectedHeader).toBeUndefined();

    expect(jwe.protectedHeader).toStrictEqual(algEncZipJkuKidHeader);
    expect(jwe.unprotectedHeader).toBeUndefined();
  });

  it('should return the deserialized General JSON Web Encryption from a Compressed Unprotected Detached Token with no Additional Authenticated Data.', async () => {
    let jwe!: GeneralJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(compressedUnprotectedDetachedTokenNoAad, {
        detachedCiphertext: compressedCiphertext,
        recipients: [{ jwk }],
      });
    }).resolves.not.toThrow();

    expect(jwe.plaintext).toStrictEqual(plaintext);

    expect(jwe.recipients).toBeArrayOfSize(1);

    expect(jwe.recipients[0]!.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.recipients[0]!.header.parameters).toStrictEqual(algEncZipJkuKidHeader);
    expect(jwe.recipients[0]!.recipientUnprotectedHeader).toBeUndefined();

    expect(jwe.protectedHeader).toBeUndefined();
    expect(jwe.unprotectedHeader).toStrictEqual(algEncZipJkuKidHeader);
  });

  it('should return the deserialized General JSON Web Encryption from a Compressed Recipient Detached Token with no Additional Authenticated Data.', async () => {
    let jwe!: GeneralJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(compressedRecipientDetachedTokenNoAad, {
        detachedCiphertext: compressedCiphertext,
        recipients: [{ jwk }],
      });
    }).resolves.not.toThrow();

    expect(jwe.plaintext).toStrictEqual(plaintext);

    expect(jwe.recipients).toBeArrayOfSize(1);

    expect(jwe.recipients[0]!.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.recipients[0]!.header.parameters).toStrictEqual(algEncZipJkuKidHeader);
    expect(jwe.recipients[0]!.recipientUnprotectedHeader).toStrictEqual(algEncZipJkuKidHeader);

    expect(jwe.protectedHeader).toBeUndefined();
    expect(jwe.unprotectedHeader).toBeUndefined();
  });

  it('should return the deserialized General JSON Web Encryption from a Compressed Protected and Unprotected Detached Token with no Additional Authenticated Data.', async () => {
    let jwe!: GeneralJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(compressedProtectedAndUnprotectedDetachedTokenNoAad, {
        detachedCiphertext: compressedCiphertext,
        recipients: [{ jwk }],
      });
    }).resolves.not.toThrow();

    expect(jwe.plaintext).toStrictEqual(plaintext);

    expect(jwe.recipients).toBeArrayOfSize(1);

    expect(jwe.recipients[0]!.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.recipients[0]!.header.parameters).toStrictEqual(algEncZipJkuKidHeader);
    expect(jwe.recipients[0]!.recipientUnprotectedHeader).toBeUndefined();

    expect(jwe.protectedHeader).toStrictEqual(encHeader);
    expect(jwe.unprotectedHeader).toStrictEqual(algZipJkuKidHeader);
  });

  it('should return the deserialized General JSON Web Encryption from a Compressed Protected and Recipient Detached Token with no Additional Authenticated Data.', async () => {
    let jwe!: GeneralJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(compressedProtectedAndRecipientDetachedTokenNoAad, {
        detachedCiphertext: compressedCiphertext,
        recipients: [{ jwk }],
      });
    }).resolves.not.toThrow();

    expect(jwe.plaintext).toStrictEqual(plaintext);

    expect(jwe.recipients).toBeArrayOfSize(1);

    expect(jwe.recipients[0]!.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.recipients[0]!.header.parameters).toStrictEqual(algEncZipJkuKidHeader);
    expect(jwe.recipients[0]!.recipientUnprotectedHeader).toStrictEqual(algZipJkuKidHeader);

    expect(jwe.protectedHeader).toStrictEqual(encHeader);
    expect(jwe.unprotectedHeader).toBeUndefined();
  });

  it('should return the deserialized General JSON Web Encryption from a Compressed Unprotected and Recipient Detached Token with no Additional Authenticated Data.', async () => {
    let jwe!: GeneralJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(compressedUnprotectedAndRecipientDetachedTokenNoAad, {
        detachedCiphertext: compressedCiphertext,
        recipients: [{ jwk }],
      });
    }).resolves.not.toThrow();

    expect(jwe.plaintext).toStrictEqual(plaintext);

    expect(jwe.recipients).toBeArrayOfSize(1);

    expect(jwe.recipients[0]!.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.recipients[0]!.header.parameters).toStrictEqual(algEncZipJkuKidHeader);
    expect(jwe.recipients[0]!.recipientUnprotectedHeader).toStrictEqual(algZipJkuKidHeader);

    expect(jwe.protectedHeader).toBeUndefined();
    expect(jwe.unprotectedHeader).toStrictEqual(encHeader);
  });

  it('should return the deserialized General JSON Web Encryption from a Compressed Protected, Unprotected and Recipient Detached Token with no Additional Authenticated Data.', async () => {
    let jwe!: GeneralJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(compressedFullDetachedTokenNoAad, {
        detachedCiphertext: compressedCiphertext,
        recipients: [{ jwk }],
      });
    }).resolves.not.toThrow();

    expect(jwe.plaintext).toStrictEqual(plaintext);

    expect(jwe.recipients).toBeArrayOfSize(1);

    expect(jwe.recipients[0]!.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.recipients[0]!.header.parameters).toStrictEqual(algEncZipJkuKidHeader);
    expect(jwe.recipients[0]!.recipientUnprotectedHeader).toStrictEqual(algZipKidHeader);

    expect(jwe.protectedHeader).toStrictEqual(encHeader);
    expect(jwe.unprotectedHeader).toStrictEqual(jkuHeader);
  });

  it('should return the deserialized General JSON Web Encryption from an Uncompressed Protected Attached Token with Additional Authenticated Data.', async () => {
    let jwe!: GeneralJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(uncompressedProtectedAttachedToken, { recipients: [{ jwk }] });
    }).resolves.not.toThrow();

    expect(jwe.plaintext).toStrictEqual(plaintext);

    expect(jwe.recipients).toBeArrayOfSize(1);

    expect(jwe.recipients[0]!.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.recipients[0]!.header.parameters).toStrictEqual(algEncJkuKidHeader);
    expect(jwe.recipients[0]!.recipientUnprotectedHeader).toBeUndefined();

    expect(jwe.protectedHeader).toStrictEqual(algEncJkuKidHeader);
    expect(jwe.unprotectedHeader).toBeUndefined();
  });

  it('should return the deserialized General JSON Web Encryption from an Uncompressed Unprotected Attached Token with Additional Authenticated Data.', async () => {
    let jwe!: GeneralJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(uncompressedUnprotectedAttachedToken, { recipients: [{ jwk }] });
    }).resolves.not.toThrow();

    expect(jwe.plaintext).toStrictEqual(plaintext);

    expect(jwe.recipients).toBeArrayOfSize(1);

    expect(jwe.recipients[0]!.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.recipients[0]!.header.parameters).toStrictEqual(algEncJkuKidHeader);
    expect(jwe.recipients[0]!.recipientUnprotectedHeader).toBeUndefined();

    expect(jwe.protectedHeader).toBeUndefined();
    expect(jwe.unprotectedHeader).toStrictEqual(algEncJkuKidHeader);
  });

  it('should return the deserialized General JSON Web Encryption from an Uncompressed Recipient Attached Token with Additional Authenticated Data.', async () => {
    let jwe!: GeneralJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(uncompressedRecipientAttachedToken, { recipients: [{ jwk }] });
    }).resolves.not.toThrow();

    expect(jwe.plaintext).toStrictEqual(plaintext);

    expect(jwe.recipients).toBeArrayOfSize(1);

    expect(jwe.recipients[0]!.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.recipients[0]!.header.parameters).toStrictEqual(algEncJkuKidHeader);
    expect(jwe.recipients[0]!.recipientUnprotectedHeader).toStrictEqual(algEncJkuKidHeader);

    expect(jwe.protectedHeader).toBeUndefined();
    expect(jwe.unprotectedHeader).toBeUndefined();
  });

  it('should return the deserialized General JSON Web Encryption from an Uncompressed Protected and Unprotected Attached Token with Additional Authenticated Data.', async () => {
    let jwe!: GeneralJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(uncompressedProtectedAndUnprotectedAttachedToken, { recipients: [{ jwk }] });
    }).resolves.not.toThrow();

    expect(jwe.plaintext).toStrictEqual(plaintext);

    expect(jwe.recipients).toBeArrayOfSize(1);

    expect(jwe.recipients[0]!.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.recipients[0]!.header.parameters).toStrictEqual(algEncJkuKidHeader);
    expect(jwe.recipients[0]!.recipientUnprotectedHeader).toBeUndefined();

    expect(jwe.protectedHeader).toStrictEqual(encHeader);
    expect(jwe.unprotectedHeader).toStrictEqual(algJkuKidHeader);
  });

  it('should return the deserialized General JSON Web Encryption from an Uncompressed Protected and Recipient Attached Token with Additional Authenticated Data.', async () => {
    let jwe!: GeneralJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(uncompressedProtectedAndRecipientAttachedToken, { recipients: [{ jwk }] });
    }).resolves.not.toThrow();

    expect(jwe.plaintext).toStrictEqual(plaintext);

    expect(jwe.recipients).toBeArrayOfSize(1);

    expect(jwe.recipients[0]!.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.recipients[0]!.header.parameters).toStrictEqual(algEncJkuKidHeader);
    expect(jwe.recipients[0]!.recipientUnprotectedHeader).toStrictEqual(algJkuKidHeader);

    expect(jwe.protectedHeader).toStrictEqual(encHeader);
    expect(jwe.unprotectedHeader).toBeUndefined();
  });

  it('should return the deserialized General JSON Web Encryption from an Uncompressed Unprotected and Recipient Attached Token with Additional Authenticated Data.', async () => {
    let jwe!: GeneralJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(uncompressedUnprotectedAndRecipientAttachedToken, { recipients: [{ jwk }] });
    }).resolves.not.toThrow();

    expect(jwe.plaintext).toStrictEqual(plaintext);

    expect(jwe.recipients).toBeArrayOfSize(1);

    expect(jwe.recipients[0]!.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.recipients[0]!.header.parameters).toStrictEqual(algEncJkuKidHeader);
    expect(jwe.recipients[0]!.recipientUnprotectedHeader).toStrictEqual(algJkuKidHeader);

    expect(jwe.protectedHeader).toBeUndefined();
    expect(jwe.unprotectedHeader).toStrictEqual(encHeader);
  });

  it('should return the deserialized General JSON Web Encryption from an Uncompressed Protected, Unprotected and Recipient Attached Token with Additional Authenticated Data.', async () => {
    let jwe!: GeneralJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(uncompressedFullAttachedToken, { recipients: [{ jwk }] });
    }).resolves.not.toThrow();

    expect(jwe.plaintext).toStrictEqual(plaintext);

    expect(jwe.recipients).toBeArrayOfSize(1);

    expect(jwe.recipients[0]!.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.recipients[0]!.header.parameters).toStrictEqual(algEncJkuKidHeader);
    expect(jwe.recipients[0]!.recipientUnprotectedHeader).toStrictEqual(algKidHeader);

    expect(jwe.protectedHeader).toStrictEqual(encHeader);
    expect(jwe.unprotectedHeader).toStrictEqual(jkuHeader);
  });

  it('should return the deserialized General JSON Web Encryption from an Uncompressed Protected Detached Token with Additional Authenticated Data.', async () => {
    let jwe!: GeneralJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(uncompressedProtectedDetachedToken, {
        detachedCiphertext: ciphertext,
        recipients: [{ jwk }],
      });
    }).resolves.not.toThrow();

    expect(jwe.plaintext).toStrictEqual(plaintext);

    expect(jwe.recipients).toBeArrayOfSize(1);

    expect(jwe.recipients[0]!.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.recipients[0]!.header.parameters).toStrictEqual(algEncJkuKidHeader);
    expect(jwe.recipients[0]!.recipientUnprotectedHeader).toBeUndefined();

    expect(jwe.protectedHeader).toStrictEqual(algEncJkuKidHeader);
    expect(jwe.unprotectedHeader).toBeUndefined();
  });

  it('should return the deserialized General JSON Web Encryption from an Uncompressed Unprotected Detached Token with Additional Authenticated Data.', async () => {
    let jwe!: GeneralJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(uncompressedUnprotectedDetachedToken, {
        detachedCiphertext: ciphertext,
        recipients: [{ jwk }],
      });
    }).resolves.not.toThrow();

    expect(jwe.plaintext).toStrictEqual(plaintext);

    expect(jwe.recipients).toBeArrayOfSize(1);

    expect(jwe.recipients[0]!.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.recipients[0]!.header.parameters).toStrictEqual(algEncJkuKidHeader);
    expect(jwe.recipients[0]!.recipientUnprotectedHeader).toBeUndefined();

    expect(jwe.protectedHeader).toBeUndefined();
    expect(jwe.unprotectedHeader).toStrictEqual(algEncJkuKidHeader);
  });

  it('should return the deserialized General JSON Web Encryption from an Uncompressed Recipient Detached Token with Additional Authenticated Data.', async () => {
    let jwe!: GeneralJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(uncompressedRecipientDetachedToken, {
        detachedCiphertext: ciphertext,
        recipients: [{ jwk }],
      });
    }).resolves.not.toThrow();

    expect(jwe.plaintext).toStrictEqual(plaintext);

    expect(jwe.recipients).toBeArrayOfSize(1);

    expect(jwe.recipients[0]!.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.recipients[0]!.header.parameters).toStrictEqual(algEncJkuKidHeader);
    expect(jwe.recipients[0]!.recipientUnprotectedHeader).toStrictEqual(algEncJkuKidHeader);

    expect(jwe.protectedHeader).toBeUndefined();
    expect(jwe.unprotectedHeader).toBeUndefined();
  });

  it('should return the deserialized General JSON Web Encryption from an Uncompressed Protected and Unprotected Detached Token with Additional Authenticated Data.', async () => {
    let jwe!: GeneralJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(uncompressedProtectedAndUnprotectedDetachedToken, {
        detachedCiphertext: ciphertext,
        recipients: [{ jwk }],
      });
    }).resolves.not.toThrow();

    expect(jwe.plaintext).toStrictEqual(plaintext);

    expect(jwe.recipients).toBeArrayOfSize(1);

    expect(jwe.recipients[0]!.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.recipients[0]!.header.parameters).toStrictEqual(algEncJkuKidHeader);
    expect(jwe.recipients[0]!.recipientUnprotectedHeader).toBeUndefined();

    expect(jwe.protectedHeader).toStrictEqual(encHeader);
    expect(jwe.unprotectedHeader).toStrictEqual(algJkuKidHeader);
  });

  it('should return the deserialized General JSON Web Encryption from an Uncompressed Protected and Recipient Detached Token with Additional Authenticated Data.', async () => {
    let jwe!: GeneralJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(uncompressedProtectedAndRecipientDetachedToken, {
        detachedCiphertext: ciphertext,
        recipients: [{ jwk }],
      });
    }).resolves.not.toThrow();

    expect(jwe.plaintext).toStrictEqual(plaintext);

    expect(jwe.recipients).toBeArrayOfSize(1);

    expect(jwe.recipients[0]!.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.recipients[0]!.header.parameters).toStrictEqual(algEncJkuKidHeader);
    expect(jwe.recipients[0]!.recipientUnprotectedHeader).toStrictEqual(algJkuKidHeader);

    expect(jwe.protectedHeader).toStrictEqual(encHeader);
    expect(jwe.unprotectedHeader).toBeUndefined();
  });

  it('should return the deserialized General JSON Web Encryption from an Uncompressed Unprotected and Recipient Detached Token with Additional Authenticated Data.', async () => {
    let jwe!: GeneralJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(uncompressedUnprotectedAndRecipientDetachedToken, {
        detachedCiphertext: ciphertext,
        recipients: [{ jwk }],
      });
    }).resolves.not.toThrow();

    expect(jwe.plaintext).toStrictEqual(plaintext);

    expect(jwe.recipients).toBeArrayOfSize(1);

    expect(jwe.recipients[0]!.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.recipients[0]!.header.parameters).toStrictEqual(algEncJkuKidHeader);
    expect(jwe.recipients[0]!.recipientUnprotectedHeader).toStrictEqual(algJkuKidHeader);

    expect(jwe.protectedHeader).toBeUndefined();
    expect(jwe.unprotectedHeader).toStrictEqual(encHeader);
  });

  it('should return the deserialized General JSON Web Encryption from an Uncompressed Protected, Unprotected and Recipient Detached Token with Additional Authenticated Data.', async () => {
    let jwe!: GeneralJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(uncompressedFullDetachedToken, { detachedCiphertext: ciphertext, recipients: [{ jwk }] });
    }).resolves.not.toThrow();

    expect(jwe.plaintext).toStrictEqual(plaintext);

    expect(jwe.recipients).toBeArrayOfSize(1);

    expect(jwe.recipients[0]!.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.recipients[0]!.header.parameters).toStrictEqual(algEncJkuKidHeader);
    expect(jwe.recipients[0]!.recipientUnprotectedHeader).toStrictEqual(algKidHeader);

    expect(jwe.protectedHeader).toStrictEqual(encHeader);
    expect(jwe.unprotectedHeader).toStrictEqual(jkuHeader);
  });

  it('should return the deserialized General JSON Web Encryption from a Compressed Protected Attached Token with Additional Authenticated Data.', async () => {
    let jwe!: GeneralJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(compressedProtectedAttachedToken, { recipients: [{ jwk }] });
    }).resolves.not.toThrow();

    expect(jwe.plaintext).toStrictEqual(plaintext);

    expect(jwe.recipients).toBeArrayOfSize(1);

    expect(jwe.recipients[0]!.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.recipients[0]!.header.parameters).toStrictEqual(algEncZipJkuKidHeader);
    expect(jwe.recipients[0]!.recipientUnprotectedHeader).toBeUndefined();

    expect(jwe.protectedHeader).toStrictEqual(algEncZipJkuKidHeader);
    expect(jwe.unprotectedHeader).toBeUndefined();
  });

  it('should return the deserialized General JSON Web Encryption from a Compressed Unprotected Attached Token with Additional Authenticated Data.', async () => {
    let jwe!: GeneralJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(compressedUnprotectedAttachedToken, { recipients: [{ jwk }] });
    }).resolves.not.toThrow();

    expect(jwe.plaintext).toStrictEqual(plaintext);

    expect(jwe.recipients).toBeArrayOfSize(1);

    expect(jwe.recipients[0]!.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.recipients[0]!.header.parameters).toStrictEqual(algEncZipJkuKidHeader);
    expect(jwe.recipients[0]!.recipientUnprotectedHeader).toBeUndefined();

    expect(jwe.protectedHeader).toBeUndefined();
    expect(jwe.unprotectedHeader).toStrictEqual(algEncZipJkuKidHeader);
  });

  it('should return the deserialized General JSON Web Encryption from a Compressed Recipient Attached Token with Additional Authenticated Data.', async () => {
    let jwe!: GeneralJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(compressedRecipientAttachedToken, { recipients: [{ jwk }] });
    }).resolves.not.toThrow();

    expect(jwe.plaintext).toStrictEqual(plaintext);

    expect(jwe.recipients).toBeArrayOfSize(1);

    expect(jwe.recipients[0]!.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.recipients[0]!.header.parameters).toStrictEqual(algEncZipJkuKidHeader);
    expect(jwe.recipients[0]!.recipientUnprotectedHeader).toStrictEqual(algEncZipJkuKidHeader);

    expect(jwe.protectedHeader).toBeUndefined();
    expect(jwe.unprotectedHeader).toBeUndefined();
  });

  it('should return the deserialized General JSON Web Encryption from a Compressed Protected and Unprotected Attached Token with Additional Authenticated Data.', async () => {
    let jwe!: GeneralJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(compressedProtectedAndUnprotectedAttachedToken, { recipients: [{ jwk }] });
    }).resolves.not.toThrow();

    expect(jwe.plaintext).toStrictEqual(plaintext);

    expect(jwe.recipients).toBeArrayOfSize(1);

    expect(jwe.recipients[0]!.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.recipients[0]!.header.parameters).toStrictEqual(algEncZipJkuKidHeader);
    expect(jwe.recipients[0]!.recipientUnprotectedHeader).toBeUndefined();

    expect(jwe.protectedHeader).toStrictEqual(encHeader);
    expect(jwe.unprotectedHeader).toStrictEqual(algZipJkuKidHeader);
  });

  it('should return the deserialized General JSON Web Encryption from a Compressed Protected and Recipient Attached Token with Additional Authenticated Data.', async () => {
    let jwe!: GeneralJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(compressedProtectedAndRecipientAttachedToken, { recipients: [{ jwk }] });
    }).resolves.not.toThrow();

    expect(jwe.plaintext).toStrictEqual(plaintext);

    expect(jwe.recipients).toBeArrayOfSize(1);

    expect(jwe.recipients[0]!.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.recipients[0]!.header.parameters).toStrictEqual(algEncZipJkuKidHeader);
    expect(jwe.recipients[0]!.recipientUnprotectedHeader).toStrictEqual(algZipJkuKidHeader);

    expect(jwe.protectedHeader).toStrictEqual(encHeader);
    expect(jwe.unprotectedHeader).toBeUndefined();
  });

  it('should return the deserialized General JSON Web Encryption from a Compressed Unprotected and Recipient Attached Token with Additional Authenticated Data.', async () => {
    let jwe!: GeneralJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(compressedUnprotectedAndRecipientAttachedToken, { recipients: [{ jwk }] });
    }).resolves.not.toThrow();

    expect(jwe.plaintext).toStrictEqual(plaintext);

    expect(jwe.recipients).toBeArrayOfSize(1);

    expect(jwe.recipients[0]!.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.recipients[0]!.header.parameters).toStrictEqual(algEncZipJkuKidHeader);
    expect(jwe.recipients[0]!.recipientUnprotectedHeader).toStrictEqual(algZipJkuKidHeader);

    expect(jwe.protectedHeader).toBeUndefined();
    expect(jwe.unprotectedHeader).toStrictEqual(encHeader);
  });

  it('should return the deserialized General JSON Web Encryption from a Compressed Protected, Unprotected and Recipient Attached Token with Additional Authenticated Data.', async () => {
    let jwe!: GeneralJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(compressedFullAttachedToken, { recipients: [{ jwk }] });
    }).resolves.not.toThrow();

    expect(jwe.plaintext).toStrictEqual(plaintext);

    expect(jwe.recipients).toBeArrayOfSize(1);

    expect(jwe.recipients[0]!.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.recipients[0]!.header.parameters).toStrictEqual(algEncZipJkuKidHeader);
    expect(jwe.recipients[0]!.recipientUnprotectedHeader).toStrictEqual(algZipKidHeader);

    expect(jwe.protectedHeader).toStrictEqual(encHeader);
    expect(jwe.unprotectedHeader).toStrictEqual(jkuHeader);
  });

  it('should return the deserialized General JSON Web Encryption from a Compressed Protected Detached Token with Additional Authenticated Data.', async () => {
    let jwe!: GeneralJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(compressedProtectedDetachedToken, {
        detachedCiphertext: compressedCiphertext,
        recipients: [{ jwk }],
      });
    }).resolves.not.toThrow();

    expect(jwe.plaintext).toStrictEqual(plaintext);

    expect(jwe.recipients).toBeArrayOfSize(1);

    expect(jwe.recipients[0]!.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.recipients[0]!.header.parameters).toStrictEqual(algEncZipJkuKidHeader);
    expect(jwe.recipients[0]!.recipientUnprotectedHeader).toBeUndefined();

    expect(jwe.protectedHeader).toStrictEqual(algEncZipJkuKidHeader);
    expect(jwe.unprotectedHeader).toBeUndefined();
  });

  it('should return the deserialized General JSON Web Encryption from a Compressed Unprotected Detached Token with Additional Authenticated Data.', async () => {
    let jwe!: GeneralJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(compressedUnprotectedDetachedToken, {
        detachedCiphertext: compressedCiphertext,
        recipients: [{ jwk }],
      });
    }).resolves.not.toThrow();

    expect(jwe.plaintext).toStrictEqual(plaintext);

    expect(jwe.recipients).toBeArrayOfSize(1);

    expect(jwe.recipients[0]!.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.recipients[0]!.header.parameters).toStrictEqual(algEncZipJkuKidHeader);
    expect(jwe.recipients[0]!.recipientUnprotectedHeader).toBeUndefined();

    expect(jwe.protectedHeader).toBeUndefined();
    expect(jwe.unprotectedHeader).toStrictEqual(algEncZipJkuKidHeader);
  });

  it('should return the deserialized General JSON Web Encryption from a Compressed Recipient Detached Token with Additional Authenticated Data.', async () => {
    let jwe!: GeneralJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(compressedRecipientDetachedToken, {
        detachedCiphertext: compressedCiphertext,
        recipients: [{ jwk }],
      });
    }).resolves.not.toThrow();

    expect(jwe.plaintext).toStrictEqual(plaintext);

    expect(jwe.recipients).toBeArrayOfSize(1);

    expect(jwe.recipients[0]!.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.recipients[0]!.header.parameters).toStrictEqual(algEncZipJkuKidHeader);
    expect(jwe.recipients[0]!.recipientUnprotectedHeader).toStrictEqual(algEncZipJkuKidHeader);

    expect(jwe.protectedHeader).toBeUndefined();
    expect(jwe.unprotectedHeader).toBeUndefined();
  });

  it('should return the deserialized General JSON Web Encryption from a Compressed Protected and Unprotected Detached Token with Additional Authenticated Data.', async () => {
    let jwe!: GeneralJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(compressedProtectedAndUnprotectedDetachedToken, {
        detachedCiphertext: compressedCiphertext,
        recipients: [{ jwk }],
      });
    }).resolves.not.toThrow();

    expect(jwe.plaintext).toStrictEqual(plaintext);

    expect(jwe.recipients).toBeArrayOfSize(1);

    expect(jwe.recipients[0]!.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.recipients[0]!.header.parameters).toStrictEqual(algEncZipJkuKidHeader);
    expect(jwe.recipients[0]!.recipientUnprotectedHeader).toBeUndefined();

    expect(jwe.protectedHeader).toStrictEqual(encHeader);
    expect(jwe.unprotectedHeader).toStrictEqual(algZipJkuKidHeader);
  });

  it('should return the deserialized General JSON Web Encryption from a Compressed Protected and Recipient Detached Token with Additional Authenticated Data.', async () => {
    let jwe!: GeneralJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(compressedProtectedAndRecipientDetachedToken, {
        detachedCiphertext: compressedCiphertext,
        recipients: [{ jwk }],
      });
    }).resolves.not.toThrow();

    expect(jwe.plaintext).toStrictEqual(plaintext);

    expect(jwe.recipients).toBeArrayOfSize(1);

    expect(jwe.recipients[0]!.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.recipients[0]!.header.parameters).toStrictEqual(algEncZipJkuKidHeader);
    expect(jwe.recipients[0]!.recipientUnprotectedHeader).toStrictEqual(algZipJkuKidHeader);

    expect(jwe.protectedHeader).toStrictEqual(encHeader);
    expect(jwe.unprotectedHeader).toBeUndefined();
  });

  it('should return the deserialized General JSON Web Encryption from a Compressed Unprotected and Recipient Detached Token with Additional Authenticated Data.', async () => {
    let jwe!: GeneralJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(compressedUnprotectedAndRecipientDetachedToken, {
        detachedCiphertext: compressedCiphertext,
        recipients: [{ jwk }],
      });
    }).resolves.not.toThrow();

    expect(jwe.plaintext).toStrictEqual(plaintext);

    expect(jwe.recipients).toBeArrayOfSize(1);

    expect(jwe.recipients[0]!.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.recipients[0]!.header.parameters).toStrictEqual(algEncZipJkuKidHeader);
    expect(jwe.recipients[0]!.recipientUnprotectedHeader).toStrictEqual(algZipJkuKidHeader);

    expect(jwe.protectedHeader).toBeUndefined();
    expect(jwe.unprotectedHeader).toStrictEqual(encHeader);
  });

  it('should return the deserialized General JSON Web Encryption from a Compressed Protected, Unprotected and Recipient Detached Token with Additional Authenticated Data.', async () => {
    let jwe!: GeneralJsonWebEncryption;

    await expect(async () => {
      jwe = await deserialize(compressedFullDetachedToken, {
        detachedCiphertext: compressedCiphertext,
        recipients: [{ jwk }],
      });
    }).resolves.not.toThrow();

    expect(jwe.plaintext).toStrictEqual(plaintext);

    expect(jwe.recipients).toBeArrayOfSize(1);

    expect(jwe.recipients[0]!.header).toBeInstanceOf(JsonWebEncryptionHeader);
    expect(jwe.recipients[0]!.header.parameters).toStrictEqual(algEncZipJkuKidHeader);
    expect(jwe.recipients[0]!.recipientUnprotectedHeader).toStrictEqual(algZipKidHeader);

    expect(jwe.protectedHeader).toStrictEqual(encHeader);
    expect(jwe.unprotectedHeader).toStrictEqual(jkuHeader);
  });
});
