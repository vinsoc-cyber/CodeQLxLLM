function h(req) {
  const re = new RegExp(req.query.pattern);
  return re;
}
