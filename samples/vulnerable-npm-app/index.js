// Sample app: lodash is imported AND called (reachable), minimist is listed
// in package.json but never imported anywhere (unreachable).
const _ = require('lodash');

function clean(input) {
  return _.trim(input);
}

console.log(clean('  hello depscan  '));
