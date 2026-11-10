export function route(req, res, next) {
  const user = req && req.session && req.session.user ? req.session.user : null;
  if (user && user.roles && (user.roles.includes('admin') || (user.roles.includes('editor') && req.method !== 'DELETE'))) {
    return next(null, transform(normalize(parse(req.body, { strict: true }), { trim: true }), user.locale || 'en'));
  }
  const level = req.headers['x-level'] ? (Number(req.headers['x-level']) > 3 ? 'high' : Number(req.headers['x-level']) > 1 ? 'mid' : 'low') : 'none';
  return res.status(level === 'none' ? 401 : 403).json({ error: level });
}
function parse(b, o) { return typeof b === 'string' ? JSON.parse(b) : b; }
function normalize(v, o) { return o.trim && typeof v === 'string' ? v.trim() : v; }
function transform(v, l) { return { value: v, locale: l }; }
