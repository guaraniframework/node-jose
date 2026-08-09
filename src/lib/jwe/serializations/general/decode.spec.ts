import { Buffer } from 'buffer';
import https from 'https';
import { Stream } from 'stream';

import { jsonStringify } from '@guarani/primitives';

import { InvalidJsonWebEncryptionError } from '../../../errors/invalid-jsonwebencryption.error';
import { OctetSequenceJsonWebKey } from '../../../jwa/jwk/oct/octet-sequence.jsonwebkey';
import { JsonWebEncryptionHeader } from '../../jsonwebencryption-header';
import { JsonWebEncryptionHeaderParameters } from '../../jsonwebencryption-header.parameters';
import { decode } from './decode';
import { GeneralJsonWebEncryptionParameters } from './general-jsonwebencryption.parameters';
import { GeneralJsonWebEncryptionToken } from './general-jsonwebencryption.token';

const invalidTokens: any[] = [undefined, null, true, 1, 1.2, 1n, Symbol('a'), Buffer, Buffer.alloc(1), () => 1, []];

const invalidTokenFormats: any[] = [
  {},
  { iv: undefined },
  { iv: null },
  { iv: true },
  { iv: 1 },
  { iv: 1.2 },
  { iv: 1n },
  { iv: Symbol('a') },
  { iv: Buffer },
  { iv: Buffer.alloc(1) },
  { iv: () => 1 },
  { iv: {} },
  { iv: [] },
  { iv: '' },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', aad: undefined },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', aad: null },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', aad: true },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', aad: 1 },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', aad: 1.2 },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', aad: 1n },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', aad: Symbol('a') },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', aad: Buffer },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', aad: Buffer.alloc(1) },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', aad: () => 1 },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', aad: {} },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', aad: [] },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', aad: '' },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', ciphertext: undefined },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', ciphertext: null },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', ciphertext: true },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', ciphertext: 1 },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', ciphertext: 1.2 },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', ciphertext: 1n },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', ciphertext: Symbol('a') },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', ciphertext: Buffer },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', ciphertext: Buffer.alloc(1) },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', ciphertext: () => 1 },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', ciphertext: {} },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', ciphertext: [] },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', ciphertext: '' },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: undefined },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: null },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: true },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: 1 },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: 1.2 },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: 1n },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: Symbol('a') },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: Buffer },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: Buffer.alloc(1) },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: () => 1 },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: {} },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: [] },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: '' },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: 'pf7CC-iGb8R2ZstoWHErWw', protected: undefined },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: 'pf7CC-iGb8R2ZstoWHErWw', protected: null },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: 'pf7CC-iGb8R2ZstoWHErWw', protected: true },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: 'pf7CC-iGb8R2ZstoWHErWw', protected: 1 },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: 'pf7CC-iGb8R2ZstoWHErWw', protected: 1.2 },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: 'pf7CC-iGb8R2ZstoWHErWw', protected: 1n },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: 'pf7CC-iGb8R2ZstoWHErWw', protected: Symbol('a') },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: 'pf7CC-iGb8R2ZstoWHErWw', protected: Buffer },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: 'pf7CC-iGb8R2ZstoWHErWw', protected: Buffer.alloc(1) },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: 'pf7CC-iGb8R2ZstoWHErWw', protected: () => 1 },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: 'pf7CC-iGb8R2ZstoWHErWw', protected: {} },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: 'pf7CC-iGb8R2ZstoWHErWw', protected: [] },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: 'pf7CC-iGb8R2ZstoWHErWw', protected: '' },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: 'pf7CC-iGb8R2ZstoWHErWw', unprotected: undefined },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: 'pf7CC-iGb8R2ZstoWHErWw', unprotected: null },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: 'pf7CC-iGb8R2ZstoWHErWw', unprotected: true },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: 'pf7CC-iGb8R2ZstoWHErWw', unprotected: 1 },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: 'pf7CC-iGb8R2ZstoWHErWw', unprotected: 1.2 },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: 'pf7CC-iGb8R2ZstoWHErWw', unprotected: 1n },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: 'pf7CC-iGb8R2ZstoWHErWw', unprotected: 'a' },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: 'pf7CC-iGb8R2ZstoWHErWw', unprotected: Symbol('a') },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: 'pf7CC-iGb8R2ZstoWHErWw', unprotected: Buffer },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: 'pf7CC-iGb8R2ZstoWHErWw', unprotected: Buffer.alloc(1) },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: 'pf7CC-iGb8R2ZstoWHErWw', unprotected: () => 1 },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: 'pf7CC-iGb8R2ZstoWHErWw', unprotected: {} },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: 'pf7CC-iGb8R2ZstoWHErWw', unprotected: [] },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: 'pf7CC-iGb8R2ZstoWHErWw', recipients: undefined },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: 'pf7CC-iGb8R2ZstoWHErWw', recipients: null },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: 'pf7CC-iGb8R2ZstoWHErWw', recipients: true },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: 'pf7CC-iGb8R2ZstoWHErWw', recipients: 1 },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: 'pf7CC-iGb8R2ZstoWHErWw', recipients: 1.2 },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: 'pf7CC-iGb8R2ZstoWHErWw', recipients: 1n },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: 'pf7CC-iGb8R2ZstoWHErWw', recipients: 'a' },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: 'pf7CC-iGb8R2ZstoWHErWw', recipients: Symbol('a') },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: 'pf7CC-iGb8R2ZstoWHErWw', recipients: Buffer },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: 'pf7CC-iGb8R2ZstoWHErWw', recipients: Buffer.alloc(1) },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: 'pf7CC-iGb8R2ZstoWHErWw', recipients: () => 1 },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: 'pf7CC-iGb8R2ZstoWHErWw', recipients: {} },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: 'pf7CC-iGb8R2ZstoWHErWw', recipients: [] },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: 'pf7CC-iGb8R2ZstoWHErWw', recipients: [undefined] },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: 'pf7CC-iGb8R2ZstoWHErWw', recipients: [null] },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: 'pf7CC-iGb8R2ZstoWHErWw', recipients: [true] },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: 'pf7CC-iGb8R2ZstoWHErWw', recipients: [1] },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: 'pf7CC-iGb8R2ZstoWHErWw', recipients: [1.2] },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: 'pf7CC-iGb8R2ZstoWHErWw', recipients: [1n] },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: 'pf7CC-iGb8R2ZstoWHErWw', recipients: ['a'] },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: 'pf7CC-iGb8R2ZstoWHErWw', recipients: [Symbol('a')] },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: 'pf7CC-iGb8R2ZstoWHErWw', recipients: [Buffer] },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: 'pf7CC-iGb8R2ZstoWHErWw', recipients: [Buffer.alloc(1)] },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: 'pf7CC-iGb8R2ZstoWHErWw', recipients: [() => 1] },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: 'pf7CC-iGb8R2ZstoWHErWw', recipients: [[]] },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: 'pf7CC-iGb8R2ZstoWHErWw', recipients: [{}] },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: 'pf7CC-iGb8R2ZstoWHErWw', recipients: [{ header: undefined }] },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: 'pf7CC-iGb8R2ZstoWHErWw', recipients: [{ header: null }] },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: 'pf7CC-iGb8R2ZstoWHErWw', recipients: [{ header: true }] },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: 'pf7CC-iGb8R2ZstoWHErWw', recipients: [{ header: 1 }] },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: 'pf7CC-iGb8R2ZstoWHErWw', recipients: [{ header: 1.2 }] },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: 'pf7CC-iGb8R2ZstoWHErWw', recipients: [{ header: 1n }] },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: 'pf7CC-iGb8R2ZstoWHErWw', recipients: [{ header: 'a' }] },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: 'pf7CC-iGb8R2ZstoWHErWw', recipients: [{ header: Symbol('a') }] },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: 'pf7CC-iGb8R2ZstoWHErWw', recipients: [{ header: Buffer }] },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: 'pf7CC-iGb8R2ZstoWHErWw', recipients: [{ header: Buffer.alloc(1) }] },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: 'pf7CC-iGb8R2ZstoWHErWw', recipients: [{ header: () => 1 }] },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: 'pf7CC-iGb8R2ZstoWHErWw', recipients: [{ header: [] }] },
  {
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    tag: 'pf7CC-iGb8R2ZstoWHErWw',
    recipients: [{ header: {}, encrypted_key: undefined }],
  },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: 'pf7CC-iGb8R2ZstoWHErWw', recipients: [{ header: {}, encrypted_key: null }] },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: 'pf7CC-iGb8R2ZstoWHErWw', recipients: [{ header: {}, encrypted_key: true }] },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: 'pf7CC-iGb8R2ZstoWHErWw', recipients: [{ header: {}, encrypted_key: 1 }] },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: 'pf7CC-iGb8R2ZstoWHErWw', recipients: [{ header: {}, encrypted_key: 1.2 }] },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: 'pf7CC-iGb8R2ZstoWHErWw', recipients: [{ header: {}, encrypted_key: 1n }] },
  {
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    tag: 'pf7CC-iGb8R2ZstoWHErWw',
    recipients: [{ header: {}, encrypted_key: Symbol('a') }],
  },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: 'pf7CC-iGb8R2ZstoWHErWw', recipients: [{ header: {}, encrypted_key: Buffer }] },
  {
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    tag: 'pf7CC-iGb8R2ZstoWHErWw',
    recipients: [{ header: {}, encrypted_key: Buffer.alloc(1) }],
  },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: 'pf7CC-iGb8R2ZstoWHErWw', recipients: [{ header: {}, encrypted_key: () => 1 }] },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: 'pf7CC-iGb8R2ZstoWHErWw', recipients: [{ header: {}, encrypted_key: {} }] },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: 'pf7CC-iGb8R2ZstoWHErWw', recipients: [{ header: {}, encrypted_key: [] }] },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: 'pf7CC-iGb8R2ZstoWHErWw', recipients: [{ header: {}, encrypted_key: '' }] },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: 'pf7CC-iGb8R2ZstoWHErWw', protected: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0' },
  { iv: 'AxY8DCtDaGlsbGljb3RoZQ', tag: 'pf7CC-iGb8R2ZstoWHErWw', protected: 'e30', recipients: [{}] },
];

const repeatedJoseHeaderParameters: Partial<JsonWebEncryptionHeaderParameters>[][] = [
  [{ alg: 'A128KW' }, { alg: 'A128KW' }, { enc: 'A128CBC-HS256' }],
  [{ alg: 'A128KW' }, { enc: 'A128CBC-HS256' }, { alg: 'A128KW' }],
  [{ enc: 'A128CBC-HS256' }, { alg: 'A128KW' }, { alg: 'A128KW' }],
  [{ alg: 'A128KW' }, { alg: 'A128KW' }, { alg: 'A128KW' }],
];

describe('decode()', () => {
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

  const encryptedKey = Buffer.from('6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ', 'base64url');
  const initializationVector = Buffer.from('AxY8DCtDaGlsbGljb3RoZQ', 'base64url');
  const ciphertext = Buffer.from('KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY', 'base64url');
  const compressedCiphertext = Buffer.from('7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA', 'base64url');
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

  it.each(invalidTokens)(
    'should throw when the provided General JSON Web Encryption Token is invalid.',
    async (token) => {
      await expect(decode(token)).rejects.toThrowWithMessage(
        TypeError,
        'The provided General JSON Web Encryption Token is invalid.',
      );
    },
  );

  it.each(invalidTokenFormats)(
    'should throw when the provided JSON Web Encryption Token has an invalid format.',
    async (token) => {
      await expect(decode(token)).rejects.toThrowWithMessage(
        InvalidJsonWebEncryptionError,
        'The provided JSON Web Encryption is invalid.',
      );
    },
  );

  it.each(repeatedJoseHeaderParameters)(
    'should throw when there are repeated JSON Web Encryption Header Parameters.',
    async (protectedHeader, unprotectedHeader, recipientUnprotectedHeader) => {
      await expect(
        decode({
          ...uncompressedFullAttachedTokenNoAad,
          protected: Buffer.from(jsonStringify(protectedHeader), 'utf8').toString('base64url'),
          unprotected: unprotectedHeader,
          recipients: [
            {
              header: recipientUnprotectedHeader,
              encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
            },
          ],
        }),
      ).rejects.toThrowWithMessage(InvalidJsonWebEncryptionError, 'The provided JSON Web Encryption is invalid.');
    },
  );

  it('should return the General JSON Web Encryption Parameters from an Uncompressed Protected Attached Token with no Additional Authenticated Data.', async () => {
    await expect(
      decode(uncompressedProtectedAttachedTokenNoAad),
    ).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      protectedHeader: algEncJkuKidHeader,
      initializationVector,
      ciphertext,
      authenticationTag: Buffer.from('pf7CC-iGb8R2ZstoWHErWw', 'base64url'),
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
          encryptedKey,
        },
      ],
    });
  });

  it('should return the General JSON Web Encryption Parameters from an Uncompressed Unprotected Attached Token with no Additional Authenticated Data.', async () => {
    await expect(
      decode(uncompressedUnprotectedAttachedTokenNoAad),
    ).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      unprotectedHeader: algEncJkuKidHeader,
      initializationVector,
      ciphertext,
      authenticationTag: Buffer.from('wOere2l7R7PoakOvvvxFCg', 'base64url'),
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
          encryptedKey,
        },
      ],
    });
  });

  it('should return the General JSON Web Encryption Parameters from an Uncompressed Recipient Attached Token with no Additional Authenticated Data.', async () => {
    await expect(
      decode(uncompressedRecipientAttachedTokenNoAad),
    ).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      initializationVector,
      ciphertext,
      authenticationTag: Buffer.from('wOere2l7R7PoakOvvvxFCg', 'base64url'),
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
          encryptedKey,
          recipientUnprotectedHeader: algEncJkuKidHeader,
        },
      ],
    });
  });

  it('should return the General JSON Web Encryption Parameters from an Uncompressed Protected and Unprotected Attached Token with no Additional Authenticated Data.', async () => {
    await expect(
      decode(uncompressedProtectedAndUnprotectedAttachedTokenNoAad),
    ).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      protectedHeader: encHeader,
      unprotectedHeader: algJkuKidHeader,
      initializationVector,
      ciphertext,
      authenticationTag: Buffer.from('Mz-VPPyU4RlcuYv1IwIvzw', 'base64url'),
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
          encryptedKey,
        },
      ],
    });
  });

  it('should return the General JSON Web Encryption Parameters from an Uncompressed Protected and Recipient Attached Token with no Additional Authenticated Data.', async () => {
    await expect(
      decode(uncompressedProtectedAndRecipientAttachedTokenNoAad),
    ).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      protectedHeader: encHeader,
      initializationVector,
      ciphertext,
      authenticationTag: Buffer.from('Mz-VPPyU4RlcuYv1IwIvzw', 'base64url'),
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
          encryptedKey,
          recipientUnprotectedHeader: algJkuKidHeader,
        },
      ],
    });
  });

  it('should return the General JSON Web Encryption Parameters from an Uncompressed Unprotected and Recipient Attached Token with no Additional Authenticated Data.', async () => {
    await expect(
      decode(uncompressedUnprotectedAndRecipientAttachedTokenNoAad),
    ).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      unprotectedHeader: encHeader,
      initializationVector,
      ciphertext,
      authenticationTag: Buffer.from('wOere2l7R7PoakOvvvxFCg', 'base64url'),
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
          encryptedKey,
          recipientUnprotectedHeader: algJkuKidHeader,
        },
      ],
    });
  });

  it('should return the General JSON Web Encryption Parameters from an Uncompressed Protected, Unprotected and Recipient Attached Token with no Additional Authenticated Data.', async () => {
    await expect(decode(uncompressedFullAttachedTokenNoAad)).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>(
      {
        protectedHeader: encHeader,
        unprotectedHeader: jkuHeader,
        initializationVector,
        ciphertext,
        authenticationTag: Buffer.from('Mz-VPPyU4RlcuYv1IwIvzw', 'base64url'),
        recipients: [
          {
            header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
            encryptedKey,
            recipientUnprotectedHeader: algKidHeader,
          },
        ],
      },
    );
  });

  it('should return the General JSON Web Encryption Parameters from an Uncompressed Protected Detached Token with no Additional Authenticated Data.', async () => {
    await expect(
      decode(uncompressedProtectedDetachedTokenNoAad),
    ).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      protectedHeader: algEncJkuKidHeader,
      initializationVector,
      authenticationTag: Buffer.from('pf7CC-iGb8R2ZstoWHErWw', 'base64url'),
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
          encryptedKey,
        },
      ],
    });
  });

  it('should return the General JSON Web Encryption Parameters from an Uncompressed Unprotected Detached Token with no Additional Authenticated Data.', async () => {
    await expect(
      decode(uncompressedUnprotectedDetachedTokenNoAad),
    ).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      unprotectedHeader: algEncJkuKidHeader,
      initializationVector,
      authenticationTag: Buffer.from('wOere2l7R7PoakOvvvxFCg', 'base64url'),
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
          encryptedKey,
        },
      ],
    });
  });

  it('should return the General JSON Web Encryption Parameters from an Uncompressed Recipient Detached Token with no Additional Authenticated Data.', async () => {
    await expect(
      decode(uncompressedRecipientDetachedTokenNoAad),
    ).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      initializationVector,
      authenticationTag: Buffer.from('wOere2l7R7PoakOvvvxFCg', 'base64url'),
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: algEncJkuKidHeader,
          encryptedKey,
        },
      ],
    });
  });

  it('should return the General JSON Web Encryption Parameters from an Uncompressed Protected and Unprotected Detached Token with no Additional Authenticated Data.', async () => {
    await expect(
      decode(uncompressedProtectedAndUnprotectedDetachedTokenNoAad),
    ).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      protectedHeader: encHeader,
      unprotectedHeader: algJkuKidHeader,
      initializationVector,
      authenticationTag: Buffer.from('Mz-VPPyU4RlcuYv1IwIvzw', 'base64url'),
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
          encryptedKey,
        },
      ],
    });
  });

  it('should return the General JSON Web Encryption Parameters from an Uncompressed Protected and Recipient Detached Token with no Additional Authenticated Data.', async () => {
    await expect(
      decode(uncompressedProtectedAndRecipientDetachedTokenNoAad),
    ).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      protectedHeader: encHeader,
      initializationVector,
      authenticationTag: Buffer.from('Mz-VPPyU4RlcuYv1IwIvzw', 'base64url'),
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: algJkuKidHeader,
          encryptedKey,
        },
      ],
    });
  });

  it('should return the General JSON Web Encryption Parameters from an Uncompressed Unprotected and Recipient Detached Token with no Additional Authenticated Data.', async () => {
    await expect(
      decode(uncompressedUnprotectedAndRecipientDetachedTokenNoAad),
    ).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      unprotectedHeader: encHeader,
      initializationVector,
      authenticationTag: Buffer.from('wOere2l7R7PoakOvvvxFCg', 'base64url'),
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: algJkuKidHeader,
          encryptedKey,
        },
      ],
    });
  });

  it('should return the General JSON Web Encryption Parameters from an Uncompressed Protected, Unprotected and Recipient Detached Token with no Additional Authenticated Data.', async () => {
    await expect(decode(uncompressedFullDetachedTokenNoAad)).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>(
      {
        protectedHeader: encHeader,
        unprotectedHeader: jkuHeader,
        initializationVector,
        authenticationTag: Buffer.from('Mz-VPPyU4RlcuYv1IwIvzw', 'base64url'),
        recipients: [
          {
            header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
            recipientUnprotectedHeader: algKidHeader,
            encryptedKey,
          },
        ],
      },
    );
  });

  it('should return the General JSON Web Encryption Parameters from a Compressed Protected Attached Token with no Additional Authenticated Data.', async () => {
    await expect(
      decode(compressedProtectedAttachedTokenNoAad),
    ).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      protectedHeader: algEncZipJkuKidHeader,
      initializationVector,
      ciphertext: compressedCiphertext,
      authenticationTag: Buffer.from('8nmSbluZF1Ws1sABt49r6Q', 'base64url'),
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
          encryptedKey,
        },
      ],
    });
  });

  it('should return the General JSON Web Encryption Parameters from a Compressed Unprotected Attached Token with no Additional Authenticated Data.', async () => {
    await expect(
      decode(compressedUnprotectedAttachedTokenNoAad),
    ).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      unprotectedHeader: algEncZipJkuKidHeader,
      initializationVector,
      ciphertext: compressedCiphertext,
      authenticationTag: Buffer.from('6mQsBNyxIUzsP37fC54ZjQ', 'base64url'),
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
          encryptedKey,
        },
      ],
    });
  });

  it('should return the General JSON Web Encryption Parameters from a Compressed Recipient Attached Token with no Additional Authenticated Data.', async () => {
    await expect(
      decode(compressedRecipientAttachedTokenNoAad),
    ).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      initializationVector,
      ciphertext: compressedCiphertext,
      authenticationTag: Buffer.from('6mQsBNyxIUzsP37fC54ZjQ', 'base64url'),
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
          encryptedKey,
          recipientUnprotectedHeader: algEncZipJkuKidHeader,
        },
      ],
    });
  });

  it('should return the General JSON Web Encryption Parameters from a Compressed Protected and Unprotected Attached Token with no Additional Authenticated Data.', async () => {
    await expect(
      decode(compressedProtectedAndUnprotectedAttachedTokenNoAad),
    ).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      protectedHeader: encHeader,
      unprotectedHeader: algZipJkuKidHeader,
      initializationVector,
      ciphertext: compressedCiphertext,
      authenticationTag: Buffer.from('FVFsNAUL3jgdAmZnSVxAFQ', 'base64url'),
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
          encryptedKey,
        },
      ],
    });
  });

  it('should return the General JSON Web Encryption Parameters from a Compressed Protected and Recipient Attached Token with no Additional Authenticated Data.', async () => {
    await expect(
      decode(compressedProtectedAndRecipientAttachedTokenNoAad),
    ).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      protectedHeader: encHeader,
      initializationVector,
      ciphertext: compressedCiphertext,
      authenticationTag: Buffer.from('FVFsNAUL3jgdAmZnSVxAFQ', 'base64url'),
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
          encryptedKey,
          recipientUnprotectedHeader: algZipJkuKidHeader,
        },
      ],
    });
  });

  it('should return the General JSON Web Encryption Parameters from a Compressed Unprotected and Recipient Attached Token with no Additional Authenticated Data.', async () => {
    await expect(
      decode(compressedUnprotectedAndRecipientAttachedTokenNoAad),
    ).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      unprotectedHeader: encHeader,
      initializationVector,
      ciphertext: compressedCiphertext,
      authenticationTag: Buffer.from('6mQsBNyxIUzsP37fC54ZjQ', 'base64url'),
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
          encryptedKey,
          recipientUnprotectedHeader: algZipJkuKidHeader,
        },
      ],
    });
  });

  it('should return the General JSON Web Encryption Parameters from a Compressed Protected, Unprotected and Recipient Attached Token with no Additional Authenticated Data.', async () => {
    await expect(decode(compressedFullAttachedTokenNoAad)).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      protectedHeader: encHeader,
      unprotectedHeader: jkuHeader,
      initializationVector,
      ciphertext: compressedCiphertext,
      authenticationTag: Buffer.from('FVFsNAUL3jgdAmZnSVxAFQ', 'base64url'),
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
          encryptedKey,
          recipientUnprotectedHeader: algZipKidHeader,
        },
      ],
    });
  });

  it('should return the General JSON Web Encryption Parameters from a Compressed Protected Detached Token with no Additional Authenticated Data.', async () => {
    await expect(
      decode(compressedProtectedDetachedTokenNoAad),
    ).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      protectedHeader: algEncZipJkuKidHeader,
      initializationVector,
      authenticationTag: Buffer.from('8nmSbluZF1Ws1sABt49r6Q', 'base64url'),
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
          encryptedKey,
        },
      ],
    });
  });

  it('should return the General JSON Web Encryption Parameters from a Compressed Unprotected Detached Token with no Additional Authenticated Data.', async () => {
    await expect(
      decode(compressedUnprotectedDetachedTokenNoAad),
    ).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      unprotectedHeader: algEncZipJkuKidHeader,
      initializationVector,
      authenticationTag: Buffer.from('6mQsBNyxIUzsP37fC54ZjQ', 'base64url'),
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
          encryptedKey,
        },
      ],
    });
  });

  it('should return the General JSON Web Encryption Parameters from a Compressed Recipient Detached Token with no Additional Authenticated Data.', async () => {
    await expect(
      decode(compressedRecipientDetachedTokenNoAad),
    ).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      initializationVector,
      authenticationTag: Buffer.from('6mQsBNyxIUzsP37fC54ZjQ', 'base64url'),
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: algEncZipJkuKidHeader,
          encryptedKey,
        },
      ],
    });
  });

  it('should return the General JSON Web Encryption Parameters from a Compressed Protected and Unprotected Detached Token with no Additional Authenticated Data.', async () => {
    await expect(
      decode(compressedProtectedAndUnprotectedDetachedTokenNoAad),
    ).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      protectedHeader: encHeader,
      unprotectedHeader: algZipJkuKidHeader,
      initializationVector,
      authenticationTag: Buffer.from('FVFsNAUL3jgdAmZnSVxAFQ', 'base64url'),
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
          encryptedKey,
        },
      ],
    });
  });

  it('should return the General JSON Web Encryption Parameters from a Compressed Protected and Recipient Detached Token with no Additional Authenticated Data.', async () => {
    await expect(
      decode(compressedProtectedAndRecipientDetachedTokenNoAad),
    ).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      protectedHeader: encHeader,
      initializationVector,
      authenticationTag: Buffer.from('FVFsNAUL3jgdAmZnSVxAFQ', 'base64url'),
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: algZipJkuKidHeader,
          encryptedKey,
        },
      ],
    });
  });

  it('should return the General JSON Web Encryption Parameters from a Compressed Unprotected and Recipient Detached Token with no Additional Authenticated Data.', async () => {
    await expect(
      decode(compressedUnprotectedAndRecipientDetachedTokenNoAad),
    ).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      unprotectedHeader: encHeader,
      initializationVector,
      authenticationTag: Buffer.from('6mQsBNyxIUzsP37fC54ZjQ', 'base64url'),
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: algZipJkuKidHeader,
          encryptedKey,
        },
      ],
    });
  });

  it('should return the General JSON Web Encryption Parameters from a Compressed Protected, Unprotected and Recipient Detached Token with no Additional Authenticated Data.', async () => {
    await expect(decode(compressedFullDetachedTokenNoAad)).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      protectedHeader: encHeader,
      unprotectedHeader: jkuHeader,
      initializationVector,
      authenticationTag: Buffer.from('FVFsNAUL3jgdAmZnSVxAFQ', 'base64url'),
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: algZipKidHeader,
          encryptedKey,
        },
      ],
    });
  });

  it('should return the General JSON Web Encryption Parameters from an Uncompressed Protected Attached Token with Additional Authenticated Data.', async () => {
    await expect(decode(uncompressedProtectedAttachedToken)).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>(
      {
        protectedHeader: algEncJkuKidHeader,
        initializationVector,
        additionalAuthenticatedData,
        ciphertext,
        authenticationTag: Buffer.from('2WcnJIVXlq2EYEbHWKr-7g', 'base64url'),
        recipients: [
          {
            header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
            encryptedKey,
          },
        ],
      },
    );
  });

  it('should return the General JSON Web Encryption Parameters from an Uncompressed Unprotected Attached Token with Additional Authenticated Data.', async () => {
    await expect(
      decode(uncompressedUnprotectedAttachedToken),
    ).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      unprotectedHeader: algEncJkuKidHeader,
      initializationVector,
      additionalAuthenticatedData,
      ciphertext,
      authenticationTag: Buffer.from('W77Q108vf3uFnX_LmZPIlA', 'base64url'),
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
          encryptedKey,
        },
      ],
    });
  });

  it('should return the General JSON Web Encryption Parameters from an Uncompressed Recipient Attached Token with Additional Authenticated Data.', async () => {
    await expect(decode(uncompressedRecipientAttachedToken)).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>(
      {
        initializationVector,
        additionalAuthenticatedData,
        ciphertext,
        authenticationTag: Buffer.from('W77Q108vf3uFnX_LmZPIlA', 'base64url'),
        recipients: [
          {
            header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
            recipientUnprotectedHeader: algEncJkuKidHeader,
            encryptedKey,
          },
        ],
      },
    );
  });

  it('should return the General JSON Web Encryption Parameters from an Uncompressed Protected and Unprotected Attached Token with Additional Authenticated Data.', async () => {
    await expect(
      decode(uncompressedProtectedAndUnprotectedAttachedToken),
    ).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      protectedHeader: encHeader,
      unprotectedHeader: algJkuKidHeader,
      initializationVector,
      additionalAuthenticatedData,
      ciphertext,
      authenticationTag: Buffer.from('ULYMNP5lrIthBrdvAIzyqg', 'base64url'),
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
          encryptedKey,
        },
      ],
    });
  });

  it('should return the General JSON Web Encryption Parameters from an Uncompressed Protected and Recipient Attached Token with Additional Authenticated Data.', async () => {
    await expect(
      decode(uncompressedProtectedAndRecipientAttachedToken),
    ).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      protectedHeader: encHeader,
      initializationVector,
      additionalAuthenticatedData,
      ciphertext,
      authenticationTag: Buffer.from('ULYMNP5lrIthBrdvAIzyqg', 'base64url'),
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: algJkuKidHeader,
          encryptedKey,
        },
      ],
    });
  });

  it('should return the General JSON Web Encryption Parameters from an Uncompressed Unprotected and Recipient Attached Token with Additional Authenticated Data.', async () => {
    await expect(
      decode(uncompressedUnprotectedAndRecipientAttachedToken),
    ).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      unprotectedHeader: encHeader,
      initializationVector,
      additionalAuthenticatedData,
      ciphertext,
      authenticationTag: Buffer.from('W77Q108vf3uFnX_LmZPIlA', 'base64url'),
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: algJkuKidHeader,
          encryptedKey,
        },
      ],
    });
  });

  it('should return the General JSON Web Encryption Parameters from an Uncompressed Protected, Unprotected and Recipient Attached Token with Additional Authenticated Data.', async () => {
    await expect(decode(uncompressedFullAttachedToken)).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      protectedHeader: encHeader,
      unprotectedHeader: jkuHeader,
      initializationVector,
      additionalAuthenticatedData,
      ciphertext,
      authenticationTag: Buffer.from('ULYMNP5lrIthBrdvAIzyqg', 'base64url'),
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: algKidHeader,
          encryptedKey,
        },
      ],
    });
  });

  it('should return the General JSON Web Encryption Parameters from an Uncompressed Protected Detached Token with Additional Authenticated Data.', async () => {
    await expect(decode(uncompressedProtectedDetachedToken)).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>(
      {
        protectedHeader: algEncJkuKidHeader,
        additionalAuthenticatedData,
        initializationVector,
        authenticationTag: Buffer.from('2WcnJIVXlq2EYEbHWKr-7g', 'base64url'),
        recipients: [
          {
            header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
            encryptedKey,
          },
        ],
      },
    );
  });

  it('should return the General JSON Web Encryption Parameters from an Uncompressed Unprotected Detached Token with Additional Authenticated Data.', async () => {
    await expect(
      decode(uncompressedUnprotectedDetachedToken),
    ).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      unprotectedHeader: algEncJkuKidHeader,
      additionalAuthenticatedData,
      initializationVector,
      authenticationTag: Buffer.from('W77Q108vf3uFnX_LmZPIlA', 'base64url'),
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
          encryptedKey,
        },
      ],
    });
  });

  it('should return the General JSON Web Encryption Parameters from an Uncompressed Recipient Detached Token with Additional Authenticated Data.', async () => {
    await expect(decode(uncompressedRecipientDetachedToken)).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>(
      {
        additionalAuthenticatedData,
        initializationVector,
        authenticationTag: Buffer.from('W77Q108vf3uFnX_LmZPIlA', 'base64url'),
        recipients: [
          {
            header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
            encryptedKey,
            recipientUnprotectedHeader: algEncJkuKidHeader,
          },
        ],
      },
    );
  });

  it('should return the General JSON Web Encryption Parameters from an Uncompressed Protected and Unprotected Detached Token with Additional Authenticated Data.', async () => {
    await expect(
      decode(uncompressedProtectedAndUnprotectedDetachedToken),
    ).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      protectedHeader: encHeader,
      unprotectedHeader: algJkuKidHeader,
      additionalAuthenticatedData,
      initializationVector,
      authenticationTag: Buffer.from('ULYMNP5lrIthBrdvAIzyqg', 'base64url'),
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
          encryptedKey,
        },
      ],
    });
  });

  it('should return the General JSON Web Encryption Parameters from an Uncompressed Protected and Recipient Detached Token with Additional Authenticated Data.', async () => {
    await expect(
      decode(uncompressedProtectedAndRecipientDetachedToken),
    ).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      protectedHeader: encHeader,
      additionalAuthenticatedData,
      initializationVector,
      authenticationTag: Buffer.from('ULYMNP5lrIthBrdvAIzyqg', 'base64url'),
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
          encryptedKey,
          recipientUnprotectedHeader: algJkuKidHeader,
        },
      ],
    });
  });

  it('should return the General JSON Web Encryption Parameters from an Uncompressed Unprotected and Recipient Detached Token with Additional Authenticated Data.', async () => {
    await expect(
      decode(uncompressedUnprotectedAndRecipientDetachedToken),
    ).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      unprotectedHeader: encHeader,
      additionalAuthenticatedData,
      initializationVector,
      authenticationTag: Buffer.from('W77Q108vf3uFnX_LmZPIlA', 'base64url'),
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
          encryptedKey,
          recipientUnprotectedHeader: algJkuKidHeader,
        },
      ],
    });
  });

  it('should return the General JSON Web Encryption Parameters from an Uncompressed Protected, Unprotected and Recipient Detached Token with Additional Authenticated Data.', async () => {
    await expect(decode(uncompressedFullDetachedToken)).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      protectedHeader: encHeader,
      unprotectedHeader: jkuHeader,
      additionalAuthenticatedData,
      initializationVector,
      authenticationTag: Buffer.from('ULYMNP5lrIthBrdvAIzyqg', 'base64url'),
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
          encryptedKey,
          recipientUnprotectedHeader: algKidHeader,
        },
      ],
    });
  });

  it('should return the General JSON Web Encryption Parameters from a Compressed Protected Attached Token with Additional Authenticated Data.', async () => {
    await expect(decode(compressedProtectedAttachedToken)).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      protectedHeader: algEncZipJkuKidHeader,
      additionalAuthenticatedData,
      initializationVector,
      ciphertext: compressedCiphertext,
      authenticationTag: Buffer.from('SRoHlcdRqnsVScLWNZIwtA', 'base64url'),
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
          encryptedKey,
        },
      ],
    });
  });

  it('should return the General JSON Web Encryption Parameters from a Compressed Unprotected Attached Token with Additional Authenticated Data.', async () => {
    await expect(decode(compressedUnprotectedAttachedToken)).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>(
      {
        unprotectedHeader: algEncZipJkuKidHeader,
        additionalAuthenticatedData,
        initializationVector,
        ciphertext: compressedCiphertext,
        authenticationTag: Buffer.from('0Z9lyKxM6Rz-6zCUcfNOmQ', 'base64url'),
        recipients: [
          {
            header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
            encryptedKey,
          },
        ],
      },
    );
  });

  it('should return the General JSON Web Encryption Parameters from a Compressed Recipient Attached Token with Additional Authenticated Data.', async () => {
    await expect(decode(compressedRecipientAttachedToken)).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      additionalAuthenticatedData,
      initializationVector,
      ciphertext: compressedCiphertext,
      authenticationTag: Buffer.from('0Z9lyKxM6Rz-6zCUcfNOmQ', 'base64url'),
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: algEncZipJkuKidHeader,
          encryptedKey,
        },
      ],
    });
  });

  it('should return the General JSON Web Encryption Parameters from a Compressed Protected and Unprotected Attached Token with Additional Authenticated Data.', async () => {
    await expect(
      decode(compressedProtectedAndUnprotectedAttachedToken),
    ).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      protectedHeader: encHeader,
      unprotectedHeader: algZipJkuKidHeader,
      additionalAuthenticatedData,
      initializationVector,
      ciphertext: compressedCiphertext,
      authenticationTag: Buffer.from('1IIFfjlJQ4EkqwKhBdlY5w', 'base64url'),
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
          encryptedKey,
        },
      ],
    });
  });

  it('should return the General JSON Web Encryption Parameters from a Compressed Protected and Recipient Attached Token with Additional Authenticated Data.', async () => {
    await expect(
      decode(compressedProtectedAndRecipientAttachedToken),
    ).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      protectedHeader: encHeader,
      additionalAuthenticatedData,
      initializationVector,
      ciphertext: compressedCiphertext,
      authenticationTag: Buffer.from('1IIFfjlJQ4EkqwKhBdlY5w', 'base64url'),
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: algZipJkuKidHeader,
          encryptedKey,
        },
      ],
    });
  });

  it('should return the General JSON Web Encryption Parameters from a Compressed Unprotected and Recipient Attached Token with Additional Authenticated Data.', async () => {
    await expect(
      decode(compressedUnprotectedAndRecipientAttachedToken),
    ).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      unprotectedHeader: encHeader,
      additionalAuthenticatedData,
      initializationVector,
      ciphertext: compressedCiphertext,
      authenticationTag: Buffer.from('0Z9lyKxM6Rz-6zCUcfNOmQ', 'base64url'),
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: algZipJkuKidHeader,
          encryptedKey,
        },
      ],
    });
  });

  it('should return the General JSON Web Encryption Parameters from a Compressed Protected, Unprotected and Recipient Attached Token with Additional Authenticated Data.', async () => {
    await expect(decode(compressedFullAttachedToken)).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      protectedHeader: encHeader,
      unprotectedHeader: jkuHeader,
      additionalAuthenticatedData,
      initializationVector,
      ciphertext: compressedCiphertext,
      authenticationTag: Buffer.from('1IIFfjlJQ4EkqwKhBdlY5w', 'base64url'),
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: algZipKidHeader,
          encryptedKey,
        },
      ],
    });
  });

  it('should return the General JSON Web Encryption Parameters from a Compressed Protected Detached Token with Additional Authenticated Data.', async () => {
    await expect(decode(compressedProtectedDetachedToken)).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      protectedHeader: algEncZipJkuKidHeader,
      additionalAuthenticatedData,
      initializationVector,
      authenticationTag: Buffer.from('SRoHlcdRqnsVScLWNZIwtA', 'base64url'),
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
          encryptedKey,
        },
      ],
    });
  });

  it('should return the General JSON Web Encryption Parameters from a Compressed Unprotected Detached Token with Additional Authenticated Data.', async () => {
    await expect(decode(compressedUnprotectedDetachedToken)).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>(
      {
        unprotectedHeader: algEncZipJkuKidHeader,
        additionalAuthenticatedData,
        initializationVector,
        authenticationTag: Buffer.from('0Z9lyKxM6Rz-6zCUcfNOmQ', 'base64url'),
        recipients: [
          {
            header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
            encryptedKey,
          },
        ],
      },
    );
  });

  it('should return the General JSON Web Encryption Parameters from a Compressed Recipient Detached Token with Additional Authenticated Data.', async () => {
    await expect(decode(compressedRecipientDetachedToken)).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      additionalAuthenticatedData,
      initializationVector,
      authenticationTag: Buffer.from('0Z9lyKxM6Rz-6zCUcfNOmQ', 'base64url'),
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
          encryptedKey,
          recipientUnprotectedHeader: algEncZipJkuKidHeader,
        },
      ],
    });
  });

  it('should return the General JSON Web Encryption Parameters from a Compressed Protected and Unprotected Detached Token with Additional Authenticated Data.', async () => {
    await expect(
      decode(compressedProtectedAndUnprotectedDetachedToken),
    ).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      protectedHeader: encHeader,
      unprotectedHeader: algZipJkuKidHeader,
      additionalAuthenticatedData,
      initializationVector,
      authenticationTag: Buffer.from('1IIFfjlJQ4EkqwKhBdlY5w', 'base64url'),
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
          encryptedKey,
        },
      ],
    });
  });

  it('should return the General JSON Web Encryption Parameters from a Compressed Protected and Recipient Detached Token with Additional Authenticated Data.', async () => {
    await expect(
      decode(compressedProtectedAndRecipientDetachedToken),
    ).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      protectedHeader: encHeader,
      additionalAuthenticatedData,
      initializationVector,
      authenticationTag: Buffer.from('1IIFfjlJQ4EkqwKhBdlY5w', 'base64url'),
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
          encryptedKey,
          recipientUnprotectedHeader: algZipJkuKidHeader,
        },
      ],
    });
  });

  it('should return the General JSON Web Encryption Parameters from a Compressed Unprotected and Recipient Detached Token with Additional Authenticated Data.', async () => {
    await expect(
      decode(compressedUnprotectedAndRecipientDetachedToken),
    ).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      unprotectedHeader: encHeader,
      additionalAuthenticatedData,
      initializationVector,
      authenticationTag: Buffer.from('0Z9lyKxM6Rz-6zCUcfNOmQ', 'base64url'),
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
          encryptedKey,
          recipientUnprotectedHeader: algZipJkuKidHeader,
        },
      ],
    });
  });

  it('should return the General JSON Web Encryption Parameters from a Compressed Protected, Unprotected and Recipient Detached Token with Additional Authenticated Data.', async () => {
    await expect(decode(compressedFullDetachedToken)).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      protectedHeader: encHeader,
      unprotectedHeader: jkuHeader,
      additionalAuthenticatedData,
      initializationVector,
      authenticationTag: Buffer.from('1IIFfjlJQ4EkqwKhBdlY5w', 'base64url'),
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
          encryptedKey,
          recipientUnprotectedHeader: algZipKidHeader,
        },
      ],
    });
  });
});
