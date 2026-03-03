import { InvalidJoseHeaderException } from './invalid-jose-header.exception';

describe('Invalid Jose Header Exception', () => {
  it('should instantiate a new InvalidJoseHeaderException.', () => {
    let exception!: InvalidJoseHeaderException;

    expect(() => (exception = new InvalidJoseHeaderException())).not.toThrow();
    expect(exception.message).toEqual('The provided Jose Header is invalid.');
  });
});
