import { InvalidJwkException } from './invalid-jwk.exception';

describe('Invalid JWK Exception', () => {
  it('should instantiate a new InvalidJwkException.', () => {
    let exception!: InvalidJwkException;

    expect(() => (exception = new InvalidJwkException())).not.toThrow();
    expect(exception.message).toEqual('The provided JWK is invalid.');
  });
});
