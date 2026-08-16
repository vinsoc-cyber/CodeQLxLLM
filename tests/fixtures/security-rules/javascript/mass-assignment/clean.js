function create(req) {
  return User.create({ name: req.body.name, email: req.body.email });
}
