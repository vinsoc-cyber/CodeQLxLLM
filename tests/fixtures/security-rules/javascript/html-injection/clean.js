// Sanitized via DOMPurify — safe
import DOMPurify from "dompurify";
function render(el, req) {
  el.innerHTML = DOMPurify.sanitize(req.body.message);
}
