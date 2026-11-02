'use strict';

/** @import * as typedoc from 'typedoc'; */
/** @type {typedoc.TypeDocOptions} */
module.exports = {
  entryPoints: ['src/index.ts'],
  out: 'docs',
  cleanOutputDir: true,
  includeVersion: true,
  sidebarLinks: {
    GitHub: 'https://github.com/hildjj//workspaces/mock-dns-server/',
    Documentation: 'http://hildjj.github.io//workspaces/mock-dns-server/',
  },
  navigation: {
    includeCategories: false,
    includeGroups: false,
  },
  categorizeByGroup: false,
  sort: ['static-first', 'alphabetical'],
};
