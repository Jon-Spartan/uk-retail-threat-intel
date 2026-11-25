const { copyFileSync, mkdirSync } = require('node:fs');

mkdirSync('assets', { recursive: true });
for (const font of ['inter', 'jetbrains-mono']) {
  const source = 'node_modules/@fontsource-variable/' + font;
  copyFileSync(source + '/files/' + font + '-latin-wght-normal.woff2', 'assets/' + font + '.woff2');
  copyFileSync(source + '/LICENSE', 'assets/' + font + '-OFL.txt');
}
copyFileSync('node_modules/tailwindcss/LICENSE', 'assets/tailwindcss-LICENSE.txt');
