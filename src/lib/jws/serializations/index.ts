import { compact } from './compact';
import { flattened } from './flattened';
import { general } from './general';

interface JsonWebSignatureSerializations {
  readonly compact: typeof compact;
  readonly flattened: typeof flattened;
  readonly general: typeof general;
}

export const jws: JsonWebSignatureSerializations = {
  compact,
  flattened,
  general,
};
