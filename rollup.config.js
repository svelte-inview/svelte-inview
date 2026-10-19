const svelte = require('rollup-plugin-svelte');
const resolve = require('@rollup/plugin-node-resolve');
const autoPreprocess = require('svelte-preprocess');
const typescript = require('rollup-plugin-typescript2');
const fs = require('fs');
const pkg = require('./package.json');

const name = pkg.name
  .replace(/^(@\S+\/)?(svelte-)?(\S+)/, '$3')
  .replace(/^\w/, (m) => m.toUpperCase())
  .replace(/-\w/g, (m) => m[1].toUpperCase());

module.exports = {
  input: 'src/index.ts',
  external: ['svelte'],
  output: [
    { file: pkg.module, format: 'es' },
    {
      file: pkg.main,
      format: 'umd',
      name,
      globals: { svelte: 'svelte' },
      esModule: true,
    },
  ],
  plugins: [
    svelte({ preprocess: autoPreprocess() }),
    resolve(),
    typescript(),
    {
      name: 'copy-type-declarations',
      writeBundle: () => {
        fs.copyFileSync('src/index.d.ts', 'dist/index.d.ts');
        fs.copyFileSync(
          'src/additional-svelte-jsx.d.ts',
          'dist/additional-svelte-jsx.d.ts'
        );
      },
    },
  ],
};
