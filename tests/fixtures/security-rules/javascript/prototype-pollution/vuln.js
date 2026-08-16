// CWE-1321: bracket-property write keyed by req.body directly
function merge(target, req) {
  target[req.body.key] = req.body.value;
  return target;
}
module.exports = { merge };
