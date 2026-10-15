import { cpSync, mkdirSync, writeFileSync } from 'node:fs';

const target = new URL('./node_modules/svelte-inview/', import.meta.url);
mkdirSync(new URL('dist/', target), { recursive: true });
cpSync(new URL('../dist/', import.meta.url), new URL('dist/', target), {
  recursive: true,
  filter: (source) =>
    source.endsWith('.d.ts') || source.replace(/\/+$/, '').endsWith('/dist'),
});
writeFileSync(
  new URL('package.json', target),
  JSON.stringify(
    {
      name: 'svelte-inview',
      version: '4.0.4',
      types: 'dist/index.d.ts',
    },
    null,
    2
  )
);
