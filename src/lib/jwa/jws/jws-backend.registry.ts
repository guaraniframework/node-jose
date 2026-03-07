import { EcdsaJwsBackend } from './ecdsa/ecdsa-jws-backend';
import { EddsaJwsBackend } from './eddsa/eddsa-jws-backend';
import { HmacJwsBackend } from './hmac/hmac-jws-backend';
import { NoneJwsBackend } from './none/none-jws-backend';
import { RsaSsaJwsBackend } from './rsassa/rsassa-jws-backend';
import { JwsAlg } from './jws-alg.type';
import { JwsBackend } from './jws-backend';

/**
 * JWS Backend Registry.
 */
export const JWS_BACKEND_REGISTRY: Record<JwsAlg, JwsBackend> = {
  EdDSA: new EddsaJwsBackend(),
  ES256: new EcdsaJwsBackend('P-256'),
  ES384: new EcdsaJwsBackend('P-384'),
  ES512: new EcdsaJwsBackend('P-521'),
  HS256: new HmacJwsBackend(32),
  HS384: new HmacJwsBackend(48),
  HS512: new HmacJwsBackend(64),
  none: new NoneJwsBackend(),
  PS256: new RsaSsaJwsBackend('SHA256', 'RSASSA-PSS'),
  PS384: new RsaSsaJwsBackend('SHA384', 'RSASSA-PSS'),
  PS512: new RsaSsaJwsBackend('SHA512', 'RSASSA-PSS'),
  RS256: new RsaSsaJwsBackend('SHA256', 'RSASSA-PKCS1-v1_5'),
  RS384: new RsaSsaJwsBackend('SHA384', 'RSASSA-PKCS1-v1_5'),
  RS512: new RsaSsaJwsBackend('SHA512', 'RSASSA-PKCS1-v1_5'),
};
