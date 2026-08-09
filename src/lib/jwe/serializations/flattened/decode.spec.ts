import { Buffer } from 'buffer';
import https from 'https';
import { Stream } from 'stream';

import { jsonStringify } from '@guarani/primitives';

import { InvalidJsonWebEncryptionError } from '../../../errors/invalid-jsonwebencryption.error';
import { OctetSequenceJsonWebKey } from '../../../jwa/jwk/oct/octet-sequence.jsonwebkey';
import { JsonWebEncryptionHeader } from '../../jsonwebencryption-header';
import { JsonWebEncryptionHeaderParameters } from '../../jsonwebencryption-header.parameters';
import { decode } from './decode';
import { FlattenedJsonWebEncryptionParameters } from './flattened-jsonwebencryption.parameters';
import { FlattenedJsonWebEncryptionToken } from './flattened-jsonwebencryption.token';

const invalidTokens: any[] = [undefined, null, true, 1, 1.2, 1n, Symbol('a'), Buffer, Buffer.alloc(1), () => 1, []];

const invalidTokenFormats: any[] = [
  {},
  { protected: null },
  { protected: true },
  { protected: 1 },
  { protected: 1.2 },
  { protected: 1n },
  { protected: Symbol('a') },
  { protected: Buffer },
  { protected: Buffer.alloc(1) },
  { protected: () => 1 },
  { protected: {} },
  { protected: [] },
  { protected: '' },
  { protected: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0', unprotected: null },
  { protected: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0', unprotected: true },
  { protected: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0', unprotected: 1 },
  { protected: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0', unprotected: 1.2 },
  { protected: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0', unprotected: 1n },
  { protected: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0', unprotected: 'a' },
  { protected: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0', unprotected: Symbol('a') },
  { protected: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0', unprotected: Buffer },
  { protected: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0', unprotected: Buffer.alloc(1) },
  { protected: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0', unprotected: () => 1 },
  { protected: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0', unprotected: [] },
  { protected: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0', header: null },
  { protected: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0', header: true },
  { protected: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0', header: 1 },
  { protected: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0', header: 1.2 },
  { protected: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0', header: 1n },
  { protected: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0', header: 'a' },
  { protected: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0', header: Symbol('a') },
  { protected: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0', header: Buffer },
  { protected: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0', header: Buffer.alloc(1) },
  { protected: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0', header: () => 1 },
  { protected: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0', header: [] },
  { protected: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0', encrypted_key: null },
  { protected: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0', encrypted_key: true },
  { protected: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0', encrypted_key: 1 },
  { protected: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0', encrypted_key: 1.2 },
  { protected: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0', encrypted_key: 1n },
  { protected: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0', encrypted_key: Symbol('a') },
  { protected: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0', encrypted_key: Buffer },
  { protected: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0', encrypted_key: Buffer.alloc(1) },
  { protected: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0', encrypted_key: () => 1 },
  { protected: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0', encrypted_key: {} },
  { protected: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0', encrypted_key: [] },
  { protected: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0', encrypted_key: '' },
  {
    protected: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: null,
  },
  {
    protected: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: true,
  },
  {
    protected: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: 1,
  },
  {
    protected: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: 1.2,
  },
  {
    protected: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: 1n,
  },
  {
    protected: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: Symbol('a'),
  },
  {
    protected: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: Buffer,
  },
  {
    protected: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: Buffer.alloc(1),
  },
  {
    protected: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: () => 1,
  },
  {
    protected: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: {},
  },
  {
    protected: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: [],
  },
  {
    protected: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: '',
  },
  {
    protected: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    iv: null,
  },
  {
    protected: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    iv: true,
  },
  {
    protected: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    iv: 1,
  },
  {
    protected: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    iv: 1.2,
  },
  {
    protected: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    iv: 1n,
  },
  {
    protected: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    iv: Symbol('a'),
  },
  {
    protected: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    iv: Buffer,
  },
  {
    protected: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    iv: Buffer.alloc(1),
  },
  {
    protected: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    iv: () => 1,
  },
  {
    protected: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    iv: {},
  },
  {
    protected: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    iv: [],
  },
  {
    protected: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    iv: '',
  },
  {
    protected: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    tag: null,
  },
  {
    protected: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    tag: true,
  },
  {
    protected: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    tag: 1,
  },
  {
    protected: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    tag: 1.2,
  },
  {
    protected: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    tag: 1n,
  },
  {
    protected: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    tag: Symbol('a'),
  },
  {
    protected: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    tag: Buffer,
  },
  {
    protected: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    tag: Buffer.alloc(1),
  },
  {
    protected: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    tag: () => 1,
  },
  {
    protected: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    tag: {},
  },
  {
    protected: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    tag: [],
  },
  {
    protected: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    tag: '',
  },
  {
    protected: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    tag: 'pf7CC-iGb8R2ZstoWHErWw',
    ciphertext: null,
  },
  {
    protected: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    tag: 'pf7CC-iGb8R2ZstoWHErWw',
    ciphertext: true,
  },
  {
    protected: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    tag: 'pf7CC-iGb8R2ZstoWHErWw',
    ciphertext: 1,
  },
  {
    protected: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    tag: 'pf7CC-iGb8R2ZstoWHErWw',
    ciphertext: 1.2,
  },
  {
    protected: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    tag: 'pf7CC-iGb8R2ZstoWHErWw',
    ciphertext: 1n,
  },
  {
    protected: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    tag: 'pf7CC-iGb8R2ZstoWHErWw',
    ciphertext: Symbol('a'),
  },
  {
    protected: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    tag: 'pf7CC-iGb8R2ZstoWHErWw',
    ciphertext: Buffer,
  },
  {
    protected: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    tag: 'pf7CC-iGb8R2ZstoWHErWw',
    ciphertext: Buffer.alloc(1),
  },
  {
    protected: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    tag: 'pf7CC-iGb8R2ZstoWHErWw',
    ciphertext: () => 1,
  },
  {
    protected: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    tag: 'pf7CC-iGb8R2ZstoWHErWw',
    ciphertext: {},
  },
  {
    protected: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    tag: 'pf7CC-iGb8R2ZstoWHErWw',
    ciphertext: [],
  },
  {
    protected: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    tag: 'pf7CC-iGb8R2ZstoWHErWw',
    ciphertext: '',
  },
  { protected: 'e30' },
  {
    protected: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    encrypted_key: '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
    aad: 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    tag: 'pf7CC-iGb8R2ZstoWHErWw',
    ciphertext: 'KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY',
  },
];

const repeatedJoseHeaderParameters: Partial<JsonWebEncryptionHeaderParameters>[][] = [
  [{ alg: 'A128KW' }, { alg: 'A128KW' }, { enc: 'A128CBC-HS256' }],
  [{ alg: 'A128KW' }, { enc: 'A128CBC-HS256' }, { alg: 'A128KW' }],
  [{ enc: 'A128CBC-HS256' }, { alg: 'A128KW' }, { alg: 'A128KW' }],
  [{ alg: 'A128KW' }, { alg: 'A128KW' }, { alg: 'A128KW' }],
];

describe('decode()', () => {
  const missingEkToken: FlattenedJsonWebEncryptionToken = {
    protected: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    unprotected: { jku: 'https://server.example.com/keys.jwks' },
    header: { alg: 'A128KW', kid: '7' },
    aad: 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
    iv: 'AxY8DCtDaGlsbGljb3RoZQ',
    ciphertext: 'KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY',
    tag: 'U0m_YmjN04DJvceFICbCVQ',
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
    'should throw when the provided Flattened JSON Web Encryption Token is invalid.',
    async (token) => {
      await expect(decode(token)).rejects.toThrowWithMessage(
        TypeError,
        'The provided Flattened JSON Web Encryption Token is invalid.',
      );
    },
  );

  it.each(invalidTokenFormats)(
    'should throw when the provided Flattened JSON Web Encryption Token has an invalid format.',
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
          ...uncompressedProtectedAttachedTokenNoAad,
          protected: Buffer.from(jsonStringify(protectedHeader), 'utf8').toString('base64url'),
          unprotected: unprotectedHeader,
          header: recipientUnprotectedHeader,
        }),
      ).rejects.toThrowWithMessage(InvalidJsonWebEncryptionError, 'The provided JSON Web Encryption is invalid.');
    },
  );

  it('should return the Flattened JSON Web Encryption Parameters from an Uncompressed Protected Attached Token with no Additional Authenticated Data.', async () => {
    await expect(
      decode(uncompressedProtectedAttachedTokenNoAad),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      protectedHeader: algEncJkuKidHeader,
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      encryptedKey,
      initializationVector,
      ciphertext,
      authenticationTag: Buffer.from('pf7CC-iGb8R2ZstoWHErWw', 'base64url'),
    });
  });

  it('should return the Flattened JSON Web Encryption Parameters from an Uncompressed Unprotected Attached Token with no Additional Authenticated Data.', async () => {
    await expect(
      decode(uncompressedUnprotectedAttachedTokenNoAad),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      unprotectedHeader: algEncJkuKidHeader,
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      encryptedKey,
      initializationVector,
      ciphertext,
      authenticationTag: Buffer.from('wOere2l7R7PoakOvvvxFCg', 'base64url'),
    });
  });

  it('should return the Flattened JSON Web Encryption Parameters from an Uncompressed Recipient Attached Token with no Additional Authenticated Data.', async () => {
    await expect(
      decode(uncompressedRecipientAttachedTokenNoAad),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      recipientUnprotectedHeader: algEncJkuKidHeader,
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      encryptedKey,
      initializationVector,
      ciphertext,
      authenticationTag: Buffer.from('wOere2l7R7PoakOvvvxFCg', 'base64url'),
    });
  });

  it('should return the Flattened JSON Web Encryption Parameters from an Uncompressed Protected and Unprotected Attached Token with no Additional Authenticated Data.', async () => {
    await expect(
      decode(uncompressedProtectedAndUnprotectedAttachedTokenNoAad),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      protectedHeader: encHeader,
      unprotectedHeader: algJkuKidHeader,
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      encryptedKey,
      initializationVector,
      ciphertext,
      authenticationTag: Buffer.from('Mz-VPPyU4RlcuYv1IwIvzw', 'base64url'),
    });
  });

  it('should return the Flattened JSON Web Encryption Parameters from an Uncompressed Protected and Recipient Attached Token with no Additional Authenticated Data.', async () => {
    await expect(
      decode(uncompressedProtectedAndRecipientAttachedTokenNoAad),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      protectedHeader: encHeader,
      recipientUnprotectedHeader: algJkuKidHeader,
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      encryptedKey,
      initializationVector,
      ciphertext,
      authenticationTag: Buffer.from('Mz-VPPyU4RlcuYv1IwIvzw', 'base64url'),
    });
  });

  it('should return the Flattened JSON Web Encryption Parameters from an Uncompressed Unprotected and Recipient Attached Token with no Additional Authenticated Data.', async () => {
    await expect(
      decode(uncompressedUnprotectedAndRecipientAttachedTokenNoAad),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      unprotectedHeader: encHeader,
      recipientUnprotectedHeader: algJkuKidHeader,
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      encryptedKey,
      initializationVector,
      ciphertext,
      authenticationTag: Buffer.from('wOere2l7R7PoakOvvvxFCg', 'base64url'),
    });
  });

  it('should return the Flattened JSON Web Encryption Parameters from an Uncompressed Protected, Unprotected and Recipient Attached Token with no Additional Authenticated Data.', async () => {
    await expect(
      decode(uncompressedFullAttachedTokenNoAad),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      protectedHeader: encHeader,
      unprotectedHeader: jkuHeader,
      recipientUnprotectedHeader: algKidHeader,
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      encryptedKey,
      initializationVector,
      ciphertext,
      authenticationTag: Buffer.from('Mz-VPPyU4RlcuYv1IwIvzw', 'base64url'),
    });
  });

  it('should return the Flattened JSON Web Encryption Parameters from an Uncompressed Protected Detached Token with no Additional Authenticated Data.', async () => {
    await expect(
      decode(uncompressedProtectedDetachedTokenNoAad),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      protectedHeader: algEncJkuKidHeader,
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      encryptedKey,
      initializationVector,
      authenticationTag: Buffer.from('pf7CC-iGb8R2ZstoWHErWw', 'base64url'),
    });
  });

  it('should return the Flattened JSON Web Encryption Parameters from an Uncompressed Unprotected Detached Token with no Additional Authenticated Data.', async () => {
    await expect(
      decode(uncompressedUnprotectedDetachedTokenNoAad),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      unprotectedHeader: algEncJkuKidHeader,
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      encryptedKey,
      initializationVector,
      authenticationTag: Buffer.from('wOere2l7R7PoakOvvvxFCg', 'base64url'),
    });
  });

  it('should return the Flattened JSON Web Encryption Parameters from an Uncompressed Recipient Detached Token with no Additional Authenticated Data.', async () => {
    await expect(
      decode(uncompressedRecipientDetachedTokenNoAad),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      recipientUnprotectedHeader: algEncJkuKidHeader,
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      encryptedKey,
      initializationVector,
      authenticationTag: Buffer.from('wOere2l7R7PoakOvvvxFCg', 'base64url'),
    });
  });

  it('should return the Flattened JSON Web Encryption Parameters from an Uncompressed Protected and Unprotected Detached Token with no Additional Authenticated Data.', async () => {
    await expect(
      decode(uncompressedProtectedAndUnprotectedDetachedTokenNoAad),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      protectedHeader: encHeader,
      unprotectedHeader: algJkuKidHeader,
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      encryptedKey,
      initializationVector,
      authenticationTag: Buffer.from('Mz-VPPyU4RlcuYv1IwIvzw', 'base64url'),
    });
  });

  it('should return the Flattened JSON Web Encryption Parameters from an Uncompressed Protected and Recipient Detached Token with no Additional Authenticated Data.', async () => {
    await expect(
      decode(uncompressedProtectedAndRecipientDetachedTokenNoAad),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      protectedHeader: encHeader,
      recipientUnprotectedHeader: algJkuKidHeader,
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      encryptedKey,
      initializationVector,
      authenticationTag: Buffer.from('Mz-VPPyU4RlcuYv1IwIvzw', 'base64url'),
    });
  });

  it('should return the Flattened JSON Web Encryption Parameters from an Uncompressed Unprotected and Recipient Detached Token with no Additional Authenticated Data.', async () => {
    await expect(
      decode(uncompressedUnprotectedAndRecipientDetachedTokenNoAad),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      unprotectedHeader: encHeader,
      recipientUnprotectedHeader: algJkuKidHeader,
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      encryptedKey,
      initializationVector,
      authenticationTag: Buffer.from('wOere2l7R7PoakOvvvxFCg', 'base64url'),
    });
  });

  it('should return the Flattened JSON Web Encryption Parameters from an Uncompressed Protected, Unprotected and Recipient Detached Token with no Additional Authenticated Data.', async () => {
    await expect(
      decode(uncompressedFullDetachedTokenNoAad),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      protectedHeader: encHeader,
      unprotectedHeader: jkuHeader,
      recipientUnprotectedHeader: algKidHeader,
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      encryptedKey,
      initializationVector,
      authenticationTag: Buffer.from('Mz-VPPyU4RlcuYv1IwIvzw', 'base64url'),
    });
  });

  it('should return the Flattened JSON Web Encryption Parameters from a Compressed Protected Attached Token with no Additional Authenticated Data.', async () => {
    await expect(
      decode(compressedProtectedAttachedTokenNoAad),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      protectedHeader: algEncZipJkuKidHeader,
      header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
      encryptedKey,
      initializationVector,
      ciphertext: compressedCiphertext,
      authenticationTag: Buffer.from('8nmSbluZF1Ws1sABt49r6Q', 'base64url'),
    });
  });

  it('should return the Flattened JSON Web Encryption Parameters from a Compressed Unprotected Attached Token with no Additional Authenticated Data.', async () => {
    await expect(
      decode(compressedUnprotectedAttachedTokenNoAad),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      unprotectedHeader: algEncZipJkuKidHeader,
      header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
      encryptedKey,
      initializationVector,
      ciphertext: compressedCiphertext,
      authenticationTag: Buffer.from('6mQsBNyxIUzsP37fC54ZjQ', 'base64url'),
    });
  });

  it('should return the Flattened JSON Web Encryption Parameters from a Compressed Recipient Attached Token with no Additional Authenticated Data.', async () => {
    await expect(
      decode(compressedRecipientAttachedTokenNoAad),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      recipientUnprotectedHeader: algEncZipJkuKidHeader,
      header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
      encryptedKey,
      initializationVector,
      ciphertext: compressedCiphertext,
      authenticationTag: Buffer.from('6mQsBNyxIUzsP37fC54ZjQ', 'base64url'),
    });
  });

  it('should return the Flattened JSON Web Encryption Parameters from a Compressed Protected and Unprotected Attached Token with no Additional Authenticated Data.', async () => {
    await expect(
      decode(compressedProtectedAndUnprotectedAttachedTokenNoAad),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      protectedHeader: encHeader,
      unprotectedHeader: algZipJkuKidHeader,
      header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
      encryptedKey,
      initializationVector,
      ciphertext: compressedCiphertext,
      authenticationTag: Buffer.from('FVFsNAUL3jgdAmZnSVxAFQ', 'base64url'),
    });
  });

  it('should return the Flattened JSON Web Encryption Parameters from a Compressed Protected and Recipient Attached Token with no Additional Authenticated Data.', async () => {
    await expect(
      decode(compressedProtectedAndRecipientAttachedTokenNoAad),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      protectedHeader: encHeader,
      recipientUnprotectedHeader: algZipJkuKidHeader,
      header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
      encryptedKey,
      initializationVector,
      ciphertext: compressedCiphertext,
      authenticationTag: Buffer.from('FVFsNAUL3jgdAmZnSVxAFQ', 'base64url'),
    });
  });

  it('should return the Flattened JSON Web Encryption Parameters from a Compressed Unprotected and Recipient Attached Token with no Additional Authenticated Data.', async () => {
    await expect(
      decode(compressedUnprotectedAndRecipientAttachedTokenNoAad),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      unprotectedHeader: encHeader,
      recipientUnprotectedHeader: algZipJkuKidHeader,
      header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
      encryptedKey,
      initializationVector,
      ciphertext: compressedCiphertext,
      authenticationTag: Buffer.from('6mQsBNyxIUzsP37fC54ZjQ', 'base64url'),
    });
  });

  it('should return the Flattened JSON Web Encryption Parameters from a Compressed protected, Unprotected and Recipient Attached Token with no Additional Authenticated Data.', async () => {
    await expect(decode(compressedFullAttachedTokenNoAad)).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>(
      {
        protectedHeader: encHeader,
        unprotectedHeader: jkuHeader,
        recipientUnprotectedHeader: algZipKidHeader,
        header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
        encryptedKey,
        initializationVector,
        ciphertext: compressedCiphertext,
        authenticationTag: Buffer.from('FVFsNAUL3jgdAmZnSVxAFQ', 'base64url'),
      },
    );
  });

  it('should return the Flattened JSON Web Encryption Parameters from a Compressed Protected Detached Token with no Additional Authenticated Data.', async () => {
    await expect(
      decode(compressedProtectedDetachedTokenNoAad),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      protectedHeader: algEncZipJkuKidHeader,
      header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
      encryptedKey,
      initializationVector,
      authenticationTag: Buffer.from('8nmSbluZF1Ws1sABt49r6Q', 'base64url'),
    });
  });

  it('should return the Flattened JSON Web Encryption Parameters from a Compressed Unprotected Detached Token with no Additional Authenticated Data.', async () => {
    await expect(
      decode(compressedUnprotectedDetachedTokenNoAad),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      unprotectedHeader: algEncZipJkuKidHeader,
      header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
      encryptedKey,
      initializationVector,
      authenticationTag: Buffer.from('6mQsBNyxIUzsP37fC54ZjQ', 'base64url'),
    });
  });

  it('should return the Flattened JSON Web Encryption Parameters from a Compressed Recipient Detached Token with no Additional Authenticated Data.', async () => {
    await expect(
      decode(compressedRecipientDetachedTokenNoAad),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      recipientUnprotectedHeader: algEncZipJkuKidHeader,
      header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
      encryptedKey,
      initializationVector,
      authenticationTag: Buffer.from('6mQsBNyxIUzsP37fC54ZjQ', 'base64url'),
    });
  });

  it('should return the Flattened JSON Web Encryption Parameters from a Compressed Protected and Unprotected Detached Token with no Additional Authenticated Data.', async () => {
    await expect(
      decode(compressedProtectedAndUnprotectedDetachedTokenNoAad),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      protectedHeader: encHeader,
      unprotectedHeader: algZipJkuKidHeader,
      header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
      encryptedKey,
      initializationVector,
      authenticationTag: Buffer.from('FVFsNAUL3jgdAmZnSVxAFQ', 'base64url'),
    });
  });

  it('should return the Flattened JSON Web Encryption Parameters from a Compressed Protected and Recipient Detached Token with no Additional Authenticated Data.', async () => {
    await expect(
      decode(compressedProtectedAndRecipientDetachedTokenNoAad),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      protectedHeader: encHeader,
      recipientUnprotectedHeader: algZipJkuKidHeader,
      header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
      encryptedKey,
      initializationVector,
      authenticationTag: Buffer.from('FVFsNAUL3jgdAmZnSVxAFQ', 'base64url'),
    });
  });

  it('should return the Flattened JSON Web Encryption Parameters from a Compressed Unprotected and Recipient Detached Token with no Additional Authenticated Data.', async () => {
    await expect(
      decode(compressedUnprotectedAndRecipientDetachedTokenNoAad),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      unprotectedHeader: encHeader,
      recipientUnprotectedHeader: algZipJkuKidHeader,
      header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
      encryptedKey,
      initializationVector,
      authenticationTag: Buffer.from('6mQsBNyxIUzsP37fC54ZjQ', 'base64url'),
    });
  });

  it('should return the Flattened JSON Web Encryption Parameters from a Compressed protected, Unprotected and Recipient Detached Token with no Additional Authenticated Data.', async () => {
    await expect(decode(compressedFullDetachedTokenNoAad)).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>(
      {
        protectedHeader: encHeader,
        unprotectedHeader: jkuHeader,
        recipientUnprotectedHeader: algZipKidHeader,
        header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
        encryptedKey,
        initializationVector,
        authenticationTag: Buffer.from('FVFsNAUL3jgdAmZnSVxAFQ', 'base64url'),
      },
    );
  });

  it('should return the Flattened JSON Web Encryption Parameters from an Uncompressed Protected Attached Token with Additional Authenticated Data.', async () => {
    await expect(
      decode(uncompressedProtectedAttachedToken),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      protectedHeader: algEncJkuKidHeader,
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      encryptedKey,
      initializationVector,
      additionalAuthenticatedData,
      ciphertext,
      authenticationTag: Buffer.from('2WcnJIVXlq2EYEbHWKr-7g', 'base64url'),
    });
  });

  it('should return the Flattened JSON Web Encryption Parameters from an Uncompressed Unprotected Attached Token with Additional Authenticated Data.', async () => {
    await expect(
      decode(uncompressedUnprotectedAttachedToken),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      unprotectedHeader: algEncJkuKidHeader,
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      encryptedKey,
      initializationVector,
      additionalAuthenticatedData,
      ciphertext,
      authenticationTag: Buffer.from('W77Q108vf3uFnX_LmZPIlA', 'base64url'),
    });
  });

  it('should return the Flattened JSON Web Encryption Parameters from an Uncompressed Recipient Attached Token with Additional Authenticated Data.', async () => {
    await expect(
      decode(uncompressedRecipientAttachedToken),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      recipientUnprotectedHeader: algEncJkuKidHeader,
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      encryptedKey,
      initializationVector,
      additionalAuthenticatedData,
      ciphertext,
      authenticationTag: Buffer.from('W77Q108vf3uFnX_LmZPIlA', 'base64url'),
    });
  });

  it('should return the Flattened JSON Web Encryption Parameters from an Uncompressed Protected and Unprotected Attached Token with Additional Authenticated Data.', async () => {
    await expect(
      decode(uncompressedProtectedAndUnprotectedAttachedToken),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      protectedHeader: encHeader,
      unprotectedHeader: algJkuKidHeader,
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      encryptedKey,
      initializationVector,
      additionalAuthenticatedData,
      ciphertext,
      authenticationTag: Buffer.from('ULYMNP5lrIthBrdvAIzyqg', 'base64url'),
    });
  });

  it('should return the Flattened JSON Web Encryption Parameters from an Uncompressed Protected and Recipient Attached Token with Additional Authenticated Data.', async () => {
    await expect(
      decode(uncompressedProtectedAndRecipientAttachedToken),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      protectedHeader: encHeader,
      recipientUnprotectedHeader: algJkuKidHeader,
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      encryptedKey,
      initializationVector,
      additionalAuthenticatedData,
      ciphertext,
      authenticationTag: Buffer.from('ULYMNP5lrIthBrdvAIzyqg', 'base64url'),
    });
  });

  it('should return the Flattened JSON Web Encryption Parameters from an Uncompressed Unprotected and Recipient Attached Token with Additional Authenticated Data.', async () => {
    await expect(
      decode(uncompressedUnprotectedAndRecipientAttachedToken),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      unprotectedHeader: encHeader,
      recipientUnprotectedHeader: algJkuKidHeader,
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      encryptedKey,
      initializationVector,
      additionalAuthenticatedData,
      ciphertext,
      authenticationTag: Buffer.from('W77Q108vf3uFnX_LmZPIlA', 'base64url'),
    });
  });

  it('should return the Flattened JSON Web Encryption Parameters from an Uncompressed Protected, Unprotected and Recipient Attached Token with Additional Authenticated Data.', async () => {
    await expect(decode(uncompressedFullAttachedToken)).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      protectedHeader: encHeader,
      unprotectedHeader: jkuHeader,
      recipientUnprotectedHeader: algKidHeader,
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      encryptedKey,
      initializationVector,
      additionalAuthenticatedData,
      ciphertext,
      authenticationTag: Buffer.from('ULYMNP5lrIthBrdvAIzyqg', 'base64url'),
    });
  });

  it('should return the Flattened JSON Web Encryption Parameters from an Uncompressed Protected Detached Token with Additional Authenticated Data.', async () => {
    await expect(
      decode(uncompressedProtectedDetachedToken),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      protectedHeader: algEncJkuKidHeader,
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      encryptedKey,
      additionalAuthenticatedData,
      initializationVector,
      authenticationTag: Buffer.from('2WcnJIVXlq2EYEbHWKr-7g', 'base64url'),
    });
  });

  it('should return the Flattened JSON Web Encryption Parameters from an Uncompressed Unprotected Detached Token with Additional Authenticated Data.', async () => {
    await expect(
      decode(uncompressedUnprotectedDetachedToken),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      unprotectedHeader: algEncJkuKidHeader,
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      encryptedKey,
      additionalAuthenticatedData,
      initializationVector,
      authenticationTag: Buffer.from('W77Q108vf3uFnX_LmZPIlA', 'base64url'),
    });
  });

  it('should return the Flattened JSON Web Encryption Parameters from an Uncompressed Recipient Detached Token with Additional Authenticated Data.', async () => {
    await expect(
      decode(uncompressedRecipientDetachedToken),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      recipientUnprotectedHeader: algEncJkuKidHeader,
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      encryptedKey,
      additionalAuthenticatedData,
      initializationVector,
      authenticationTag: Buffer.from('W77Q108vf3uFnX_LmZPIlA', 'base64url'),
    });
  });

  it('should return the Flattened JSON Web Encryption Parameters from an Uncompressed Protected and Unprotected Detached Token with Additional Authenticated Data.', async () => {
    await expect(
      decode(uncompressedProtectedAndUnprotectedDetachedToken),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      protectedHeader: encHeader,
      unprotectedHeader: algJkuKidHeader,
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      encryptedKey,
      additionalAuthenticatedData,
      initializationVector,
      authenticationTag: Buffer.from('ULYMNP5lrIthBrdvAIzyqg', 'base64url'),
    });
  });

  it('should return the Flattened JSON Web Encryption Parameters from an Uncompressed Protected and Recipient Detached Token with Additional Authenticated Data.', async () => {
    await expect(
      decode(uncompressedProtectedAndRecipientDetachedToken),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      protectedHeader: encHeader,
      recipientUnprotectedHeader: algJkuKidHeader,
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      encryptedKey,
      additionalAuthenticatedData,
      initializationVector,
      authenticationTag: Buffer.from('ULYMNP5lrIthBrdvAIzyqg', 'base64url'),
    });
  });

  it('should return the Flattened JSON Web Encryption Parameters from an Uncompressed Unprotected and Recipient Detached Token with Additional Authenticated Data.', async () => {
    await expect(
      decode(uncompressedUnprotectedAndRecipientDetachedToken),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      unprotectedHeader: encHeader,
      recipientUnprotectedHeader: algJkuKidHeader,
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      encryptedKey,
      additionalAuthenticatedData,
      initializationVector,
      authenticationTag: Buffer.from('W77Q108vf3uFnX_LmZPIlA', 'base64url'),
    });
  });

  it('should return the Flattened JSON Web Encryption Parameters from an Uncompressed Protected, Unprotected and Recipient Detached Token with Additional Authenticated Data.', async () => {
    await expect(decode(uncompressedFullDetachedToken)).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      protectedHeader: encHeader,
      unprotectedHeader: jkuHeader,
      recipientUnprotectedHeader: algKidHeader,
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      encryptedKey,
      additionalAuthenticatedData,
      initializationVector,
      authenticationTag: Buffer.from('ULYMNP5lrIthBrdvAIzyqg', 'base64url'),
    });
  });

  it('should return the Flattened JSON Web Encryption Parameters from a Compressed Protected Attached Token with Additional Authenticated Data.', async () => {
    await expect(decode(compressedProtectedAttachedToken)).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>(
      {
        protectedHeader: algEncZipJkuKidHeader,
        header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
        encryptedKey,
        additionalAuthenticatedData,
        initializationVector,
        ciphertext: compressedCiphertext,
        authenticationTag: Buffer.from('SRoHlcdRqnsVScLWNZIwtA', 'base64url'),
      },
    );
  });

  it('should return the Flattened JSON Web Encryption Parameters from a Compressed Unprotected Attached Token with Additional Authenticated Data.', async () => {
    await expect(
      decode(compressedUnprotectedAttachedToken),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      unprotectedHeader: algEncZipJkuKidHeader,
      header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
      encryptedKey,
      additionalAuthenticatedData,
      initializationVector,
      ciphertext: compressedCiphertext,
      authenticationTag: Buffer.from('0Z9lyKxM6Rz-6zCUcfNOmQ', 'base64url'),
    });
  });

  it('should return the Flattened JSON Web Encryption Parameters from a Compressed Recipient Attached Token with Additional Authenticated Data.', async () => {
    await expect(decode(compressedRecipientAttachedToken)).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>(
      {
        recipientUnprotectedHeader: algEncZipJkuKidHeader,
        header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
        encryptedKey,
        additionalAuthenticatedData,
        initializationVector,
        ciphertext: compressedCiphertext,
        authenticationTag: Buffer.from('0Z9lyKxM6Rz-6zCUcfNOmQ', 'base64url'),
      },
    );
  });

  it('should return the Flattened JSON Web Encryption Parameters from a Compressed Protected and Unprotected Attached Token with Additional Authenticated Data.', async () => {
    await expect(
      decode(compressedProtectedAndUnprotectedAttachedToken),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      protectedHeader: encHeader,
      unprotectedHeader: algZipJkuKidHeader,
      header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
      encryptedKey,
      additionalAuthenticatedData,
      initializationVector,
      ciphertext: compressedCiphertext,
      authenticationTag: Buffer.from('1IIFfjlJQ4EkqwKhBdlY5w', 'base64url'),
    });
  });

  it('should return the Flattened JSON Web Encryption Parameters from a Compressed Protected and Recipient Attached Token with Additional Authenticated Data.', async () => {
    await expect(
      decode(compressedProtectedAndRecipientAttachedToken),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      protectedHeader: encHeader,
      recipientUnprotectedHeader: algZipJkuKidHeader,
      header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
      encryptedKey,
      additionalAuthenticatedData,
      initializationVector,
      ciphertext: compressedCiphertext,
      authenticationTag: Buffer.from('1IIFfjlJQ4EkqwKhBdlY5w', 'base64url'),
    });
  });

  it('should return the Flattened JSON Web Encryption Parameters from a Compressed Unprotected and Recipient Attached Token with Additional Authenticated Data.', async () => {
    await expect(
      decode(compressedUnprotectedAndRecipientAttachedToken),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      unprotectedHeader: encHeader,
      recipientUnprotectedHeader: algZipJkuKidHeader,
      header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
      encryptedKey,
      additionalAuthenticatedData,
      initializationVector,
      ciphertext: compressedCiphertext,
      authenticationTag: Buffer.from('0Z9lyKxM6Rz-6zCUcfNOmQ', 'base64url'),
    });
  });

  it('should return the Flattened JSON Web Encryption Parameters from a Compressed protected, Unprotected and Recipient Attached Token with Additional Authenticated Data.', async () => {
    await expect(decode(compressedFullAttachedToken)).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      protectedHeader: encHeader,
      unprotectedHeader: jkuHeader,
      recipientUnprotectedHeader: algZipKidHeader,
      header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
      encryptedKey,
      additionalAuthenticatedData,
      initializationVector,
      ciphertext: compressedCiphertext,
      authenticationTag: Buffer.from('1IIFfjlJQ4EkqwKhBdlY5w', 'base64url'),
    });
  });

  it('should return the Flattened JSON Web Encryption Parameters from a Compressed Protected Detached Token with Additional Authenticated Data.', async () => {
    await expect(decode(compressedProtectedDetachedToken)).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>(
      {
        protectedHeader: algEncZipJkuKidHeader,
        header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
        encryptedKey,
        additionalAuthenticatedData,
        initializationVector,
        authenticationTag: Buffer.from('SRoHlcdRqnsVScLWNZIwtA', 'base64url'),
      },
    );
  });

  it('should return the Flattened JSON Web Encryption Parameters from a Compressed Unprotected Detached Token with Additional Authenticated Data.', async () => {
    await expect(
      decode(compressedUnprotectedDetachedToken),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      unprotectedHeader: algEncZipJkuKidHeader,
      header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
      encryptedKey,
      additionalAuthenticatedData,
      initializationVector,
      authenticationTag: Buffer.from('0Z9lyKxM6Rz-6zCUcfNOmQ', 'base64url'),
    });
  });

  it('should return the Flattened JSON Web Encryption Parameters from a Compressed Recipient Detached Token with Additional Authenticated Data.', async () => {
    await expect(decode(compressedRecipientDetachedToken)).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>(
      {
        recipientUnprotectedHeader: algEncZipJkuKidHeader,
        header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
        encryptedKey,
        additionalAuthenticatedData,
        initializationVector,
        authenticationTag: Buffer.from('0Z9lyKxM6Rz-6zCUcfNOmQ', 'base64url'),
      },
    );
  });

  it('should return the Flattened JSON Web Encryption Parameters from a Compressed Protected and Unprotected Detached Token with Additional Authenticated Data.', async () => {
    await expect(
      decode(compressedProtectedAndUnprotectedDetachedToken),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      protectedHeader: encHeader,
      unprotectedHeader: algZipJkuKidHeader,
      header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
      encryptedKey,
      additionalAuthenticatedData,
      initializationVector,
      authenticationTag: Buffer.from('1IIFfjlJQ4EkqwKhBdlY5w', 'base64url'),
    });
  });

  it('should return the Flattened JSON Web Encryption Parameters from a Compressed Protected and Recipient Detached Token with Additional Authenticated Data.', async () => {
    await expect(
      decode(compressedProtectedAndRecipientDetachedToken),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      protectedHeader: encHeader,
      recipientUnprotectedHeader: algZipJkuKidHeader,
      header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
      encryptedKey,
      additionalAuthenticatedData,
      initializationVector,
      authenticationTag: Buffer.from('1IIFfjlJQ4EkqwKhBdlY5w', 'base64url'),
    });
  });

  it('should return the Flattened JSON Web Encryption Parameters from a Compressed Unprotected and Recipient Detached Token with Additional Authenticated Data.', async () => {
    await expect(
      decode(compressedUnprotectedAndRecipientDetachedToken),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      unprotectedHeader: encHeader,
      recipientUnprotectedHeader: algZipJkuKidHeader,
      header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
      encryptedKey,
      additionalAuthenticatedData,
      initializationVector,
      authenticationTag: Buffer.from('0Z9lyKxM6Rz-6zCUcfNOmQ', 'base64url'),
    });
  });

  it('should return the Flattened JSON Web Encryption Parameters from a Compressed protected, Unprotected and Recipient Detached Token with Additional Authenticated Data.', async () => {
    await expect(decode(compressedFullDetachedToken)).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      protectedHeader: encHeader,
      unprotectedHeader: jkuHeader,
      recipientUnprotectedHeader: algZipKidHeader,
      header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
      encryptedKey,
      additionalAuthenticatedData,
      initializationVector,
      authenticationTag: Buffer.from('1IIFfjlJQ4EkqwKhBdlY5w', 'base64url'),
    });
  });

  it('should return the Flattened JSON Web Encryption Parameters from a Token without an Encrypted Key.', async () => {
    await expect(decode(missingEkToken)).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      protectedHeader: encHeader,
      unprotectedHeader: jkuHeader,
      recipientUnprotectedHeader: algKidHeader,
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      initializationVector,
      ciphertext,
      authenticationTag: Buffer.from('U0m_YmjN04DJvceFICbCVQ', 'base64url'),
    });
  });
});
