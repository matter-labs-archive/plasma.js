export default {
  input: 'src/index.js',
  output: {
    file: 'dist/bundle.js',
    format: 'cjs',
  },
  external: [
    'assert',
    'is-buffer',
  	'js-sha3',
    'ethereumjs-util',
    'strip-hex-prefix',
  ],
};