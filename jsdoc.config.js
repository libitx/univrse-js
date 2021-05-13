module.exports = {
  source: {
    include: [
      'README.md',
      'src/',
    ]
  },
  opts: {
    recurse: true,
    destination: 'docs'
  },
  plugins: [
    'plugins/markdown'
  ],
  templates: {
    default: {
      includeDate: false
    },
    betterDocs: {
      name: 'Univrse',
      hideGenerator: false,
      navigation: [
        { label: 'Homepage', href: 'https://univrse.network' },
        { label: 'Github', href: 'https://github.com/libitx/univrse-js' }
      ]
    }
  }
}