import { InvalidJwksException } from './invalid-jwks.exception';

describe('Invalid JWK Set Exception', () => {
  it('should instantiate a new InvalidJwksException.', () => {
    let exception!: InvalidJwksException;

    expect(() => (exception = new InvalidJwksException())).not.toThrow();
    expect(exception.message).toEqual('The provided JWK Set is invalid.');
  });
});
