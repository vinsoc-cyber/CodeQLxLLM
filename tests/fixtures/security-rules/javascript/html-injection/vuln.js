// CWE-79: innerHTML written from req.body — XSS
function render(el, req) {
  el.innerHTML = req.body.message;
}
