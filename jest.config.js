/** @type {import('@ts-jest/dist/types').InitialOptionsTsJest} */
export default {
  verbose: true,
  preset: 'ts-jest/presets/default-esm',
  testEnvironment: 'node',
  roots: ['<rootDir>/tests'],
  testMatch: ['**/*.test.ts'],
  cacheDirectory: '<rootDir>/work/jest-cache',
  testTimeout: 1_000_000,
  transform: {
    '^.+\\.(t)s$': ['ts-jest', { useESM: true }],
    '^.+\\.(j)s$': 'babel-jest',
  },
  resolver: '<rootDir>/jest-resolver.cjs',
  transformIgnorePatterns: [
    '<rootDir>/node_modules/(?!(tslib|o1js/node_modules/tslib))',
  ],
  modulePathIgnorePatterns: ['<rootDir>/build/', '<rootDir>/legacy/', '<rootDir>/oldsrc/', '<rootDir>/graphify-out/'],
  moduleNameMapper: {
    '^(\\.{1,2}/.+)\\.js$': '$1',
  },
};
