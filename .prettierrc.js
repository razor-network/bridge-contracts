module.exports = {
  printWidth: 140,
  overrides: [
    {
      files: '*.sol',
      options: {
        printWidth: 140,
        singleQuote: false,
        explicitTypes: 'always',
      },
    },
  ],
  plugins: [require.resolve('prettier-plugin-solidity')],
  useTabs: false
};