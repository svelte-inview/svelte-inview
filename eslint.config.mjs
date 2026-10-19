import { defineConfig } from 'eslint/config';
import js from '@eslint/js';
import svelte from 'eslint-plugin-svelte';
import globals from 'globals';
import ts from 'typescript-eslint';
import eslintPluginPrettierRecommended from 'eslint-plugin-prettier/recommended';

export default defineConfig(
  {
    ignores: [
      'dist/**',
      'node_modules/**',
      '.rpt2_cache/**',
      'demo/.netlify/**',
      'demo/node_modules/**',
      'demo/.svelte-kit/**',
      'test-app/node_modules/**',
      'test-app/.svelte-kit/**',
      'test-app/build/**',
      'playwright-report/**',
      'test-results/**',
    ],
  },
  js.configs.recommended,
  ts.configs.recommended,
  svelte.configs.recommended,
  svelte.configs.prettier,
  {
    languageOptions: {
      globals: {
        ...globals.browser,
        ...globals.node,
      },
    },
  },
  {
    files: ['**/*.svelte', '**/*.svelte.ts', '**/*.svelte.js'],
    languageOptions: {
      parserOptions: {
        parser: ts.parser,
        extraFileExtensions: ['.svelte'],
      },
    },
    rules: {
      // TypeScript types in Svelte scripts are not JS bindings.
      'no-undef': 'off',
    },
  },
  {
    files: ['**/*.d.ts'],
    rules: {
      // Declaration merging uses empty interfaces and required type parameters.
      '@typescript-eslint/no-empty-object-type': 'off',
      '@typescript-eslint/no-unused-vars': 'off',
    },
  },
  {
    files: ['rollup.config.js'],
    rules: {
      '@typescript-eslint/no-require-imports': 'off',
    },
  },
  {
    files: ['src/inview.ts'],
    rules: {
      // Existing binding is mutated in place; this PR does not change library source.
      'prefer-const': 'off',
    },
  },
  {
    files: ['demo/**/*.svelte'],
    rules: {
      '@typescript-eslint/no-explicit-any': 'off',
      'svelte/require-each-key': 'off',
    },
  },
  {
    rules: {
      '@typescript-eslint/no-unused-expressions': [
        'error',
        { allowShortCircuit: true, allowTernary: true },
      ],
    },
  },
  eslintPluginPrettierRecommended
);
