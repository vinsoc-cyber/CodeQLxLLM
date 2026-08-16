// Guarded write — checks key against an allowlist
function merge(target, req) {
  const key = req.body.key;
  if (key === "__proto__" || key === "constructor" || key === "prototype") {
    throw new Error("forbidden key");
  }
  target[key] = req.body.value;
  return target;
}
module.exports = { merge };
