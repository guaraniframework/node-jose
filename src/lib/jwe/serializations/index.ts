import { compact } from './compact';
import { flattened } from './flattened';
import { general } from './general';

interface JsonWebEncryptionSerializations {
  readonly compact: typeof compact;
  readonly flattened: typeof flattened;
  readonly general: typeof general;
}

export const jwe: JsonWebEncryptionSerializations = {
  compact,
  flattened,
  general,
};
