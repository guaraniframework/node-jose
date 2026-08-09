import { Buffer } from 'buffer';

import { GeneralJsonWebEncryptionDeserializationOptionsRecipient } from './general-jsonwebencryption-deserialization-options-recipient';

/**
 * General JSON Web Encryption deserialization options.
 */
export interface GeneralJsonWebEncryptionDeserializationOptions {
  /**
   * Detached Ciphertext.
   */
  readonly detachedCiphertext?: Buffer;

  /**
   * Recipients options.
   */
  readonly recipients?: GeneralJsonWebEncryptionDeserializationOptionsRecipient[];
}
