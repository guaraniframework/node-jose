import 'jest-extended';

import { createDefaultPreset } from 'ts-jest';

export const testEnvironment = 'node';

export default {
  ...createDefaultPreset({
    tsconfig: 'tsconfig.spec.json',
  }),
  setupFilesAfterEnv: ['jest-extended/all'],
};
