import { JwsAlg } from '../../jwa/jws/jws-alg.type';
import { JwsBackend } from '../../jwa/jws/jws-backend';
import { JwsHeader } from './jws-header';
import { JwsHeaderParams } from './jws-header.params';

const invalidDatas: any[] = [
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
  {},
];

describe('JWS Header', () => {
  describe('constructor', () => {
    it('should return a valid jose header.', () => {
      let header!: JwsHeader;
      const params: JwsHeaderParams = { alg: 'HS256' };

      expect(() => (header = new JwsHeader(params))).not.toThrow();

      expect(header).toBeInstanceOf(JwsHeader);
      expect(header).toMatchObject(params);

      expect(header.backend).toBeInstanceOf(JwsBackend);
      expect(header.backend['alg']).toEqual<JwsAlg>('HS256');
    });
  });

  describe('isJoseHeader()', () => {
    it.each(invalidDatas)('should return false when the provided data is not a valid jose header.', (data) => {
      expect(JwsHeader.isJoseHeader(data)).toBeFalse();
    });

    it('should return true when the provided data is a valid jose header.', () => {
      expect(JwsHeader.isJoseHeader({ alg: 'RS256' })).toBeTrue();
    });
  });
});
