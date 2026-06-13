/** @type {import('jest').Config} */
module.exports = {
  testEnvironment: 'jsdom',
  transform: {
    '^.+\\.(ts|tsx)$': ['ts-jest', {
      tsconfig: {
        jsx: 'react-jsx',
        esModuleInterop: true,
        allowSyntheticDefaultImports: true,
      },
    }],
  },
  // No moduleNameMapper needed: every test file mocks @backstage/* packages
  // inline via jest.mock() calls (see ConsentPage.test.tsx, TtlCountdownChip
  // has no Backstage imports). A moduleNameMapper pointing at
  // src/__mocks__/@backstage/*.ts was removed because that directory does not
  // exist and the inline mocks in each test file are the authoritative mocks.
  testMatch: ['**/*.test.tsx', '**/*.test.ts'],
  // 'setupFilesAfterEnv' is the correct Jest key (setupFilesAfterFramework
  // was a typo — Jest silently ignores unknown top-level config keys).
  setupFilesAfterEnv: ['@testing-library/jest-dom/extend-expect'],
};
