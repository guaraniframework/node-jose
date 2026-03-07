import { InvalidJwsException } from './invalid-jws.exception';

describe('Invalid JWS Exception', () => {
  it('should instantiate a new InvalidJwsException.', () => {
    let exception!: InvalidJwsException;

    expect(() => (exception = new InvalidJwsException())).not.toThrow();
    expect(exception.message).toEqual('The provided JWS is invalid.');
  });
});
