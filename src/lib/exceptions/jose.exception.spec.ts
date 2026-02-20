import { JoseException } from './jose.exception';

describe('JOSE Exception', () => {
  it('should instantiate a new JoseException.', () => {
    expect(Reflect.construct(JoseException, [])).toBeInstanceOf(JoseException);
  });
});
