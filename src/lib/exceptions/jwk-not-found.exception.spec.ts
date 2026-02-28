import { JwkNotFoundException } from './jwk-not-found.exception';

describe('JWK Not Found Exception', () => {
  it('should instantiate a new JwkNotFoundException.', () => {
    let exception!: JwkNotFoundException;

    expect(() => (exception = new JwkNotFoundException())).not.toThrow();
    expect(exception.message).toEqual('No JWK matches the criteria at the JWK Set.');
  });
});
