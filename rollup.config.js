import commonjs from '@rollup/plugin-commonjs'
import resolve from '@rollup/plugin-node-resolve'
import json from '@rollup/plugin-json'
import { terser } from 'rollup-plugin-terser'
import banner from 'rollup-plugin-banner'
import nodePolyfills from 'rollup-plugin-node-polyfills'

export default [
  /**
   * Entry: Univrse Web
   */
  {
    input: 'src/index.js',
    output: [
      // 1. Full browser build
      {
        file: 'dist/univrse.js',
        format: 'iife',
        name: 'Univrse',
        globals: {
          bsv: 'bsvjs',
          'isomorphic-webcrypto': 'crypto'
        }
      },
      // 2. Minimised browser build
      {
        file: 'dist/univrse.min.js',
        format: 'iife',
        name: 'Univrse',
        globals: {
          bsv: 'bsvjs',
          'isomorphic-webcrypto': 'crypto'
        },
        plugins: [
          terser({
            keep_classnames: true
          })
        ]
      }
    ],
    external: ['bsv', 'isomorphic-webcrypto'],
    plugins: [
      resolve({ browser: true, preferBuiltins: false }),
      commonjs(),
      nodePolyfills(),
      json(),
      banner('Univrse - v<%= pkg.version %>\n<%= pkg.description %>\n<%= pkg.repository %>\nCopyright © <%= new Date().getFullYear() %> Chronos Labs Ltd. Apache-2.0 License')
    ]
  },

  /**
   * Entry: Univrse CJS
   */
  {
    input: 'src/index.js',
    output: {
      file: 'dist/univrse.cjs.js',
      format: 'cjs'
    },
    external: ['bsv', 'buffer'],
    plugins: [
      resolve(),
      commonjs(),
      json()
    ]
  },
]