import { encrypted } from './encrypted';
import { signed } from './signed';

interface JsonWebTokenSerializations {
  readonly encrypted: typeof encrypted;
  readonly signed: typeof signed;
}

export const jwt: JsonWebTokenSerializations = {
  encrypted,
  signed,
};
