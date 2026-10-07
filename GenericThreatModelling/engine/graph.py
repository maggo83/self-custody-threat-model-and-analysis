"""The setup as a generic graph: entities of classes declared in the ontology, containers and places, reach,
areas, catalog rows, derived attributes and a small expression language. The engine knows nothing about what a
device or a seed is; every such fact comes from the ontology table (`x-classes`) and from AccessModel.json."""
import copy
import json
import re
from functools import lru_cache
from itertools import combinations, permutations, product

import ontology
from ontology import TABLE, is_a

INF = float("inf")
PLAN = "@plan"
BUILTIN = ("class", "root", "place", "container", "catalog", "id")


def canon(v):
    return json.dumps(v, sort_keys=True) if isinstance(v, (dict, list)) else v


def flag(cls, name):
    """A boolean flag of a class or of one of its ancestors in the ontology table."""
    while cls:
        if name in TABLE.get(cls, {}):
            return TABLE[cls][name]
        cls = TABLE.get(cls, {}).get("parent")
    return None


def apply_defaults(value, node, defs):
    """Fill in the `default` keywords of the setup schema, so that conditions see the values the schema promises."""
    if "$ref" in node:
        node = defs[node["$ref"].rsplit("/", 1)[1]]
    if isinstance(value, dict):
        for key, sub in node.get("properties", {}).items():
            if key in value:
                apply_defaults(value[key], sub, defs)
            elif "default" in sub:
                value[key] = copy.deepcopy(sub["default"])
        for branch in node.get("oneOf", []) + node.get("anyOf", []):
            apply_defaults(value, branch, defs)
    elif isinstance(value, list) and "items" in node:
        for v in value:
            apply_defaults(v, node["items"], defs)


class Setup:
    """Entities by id, their classes, where they are kept, who reaches what, and attribute lookup for conditions."""

    def __init__(self, data, cat):
        self.data = copy.deepcopy(data)
        apply_defaults(self.data, ontology.SCHEMA, ontology.SCHEMA["$defs"])
        self.cat, self.model = cat, cat.access
        self.by_id = {}
        for c, coll in ontology.COLLECTIONS.items():
            for e in self.data.get(coll, []):
                self.by_id[e["id"]] = (c, e)
        for c, spec in TABLE.items():
            if "singleton" in spec:
                self.by_id[spec["singleton"]] = (c, {"id": spec["singleton"], "name": self.data.get("name", c)})
        self.places = {eid for eid, (c, _) in self.by_id.items() if flag(c, "place")}
        self._derived = {}
        self._deps = None

    # ------------------------------------------------------------------ basic access
    def cls(self, eid):
        return self.by_id[eid][0]

    def ent(self, eid):
        return self.by_id[eid][1]

    def of(self, cls):
        return [e for eid, (c, e) in self.by_id.items() if is_a(c, cls)]

    def ids_of(self, cls):
        return [eid for eid, (c, _) in self.by_id.items() if is_a(c, cls)]

    def name(self, eid):
        return self.ent(eid).get("name", eid) if eid in self.by_id else eid

    # ------------------------------------------------------------------ containment
    def container(self, eid):
        """The entity this one is kept in or runs on (`placed_by` of its class); a one-key object is unwrapped."""
        attr = flag(self.cls(eid), "placed_by")
        v = self.ent(eid).get(attr) if attr else None
        if isinstance(v, dict):
            v = next(iter(v.values()), None)
        return v

    @lru_cache(None)
    def chain(self, eid):
        """Containers from the inside out, ending at the outermost one."""
        out, cur = [], self.container(eid)
        while cur and cur not in out:
            out.append(cur)
            cur = self.container(cur)
        return tuple(out)

    def place(self, eid):
        """The nearest place (location or person) the entity is kept at; a place is its own place."""
        if eid in self.places:
            return eid
        return next((c for c in self.chain(eid) if c in self.places), None)

    def root(self, eid):
        """The outermost place."""
        if eid is None:
            return None
        return ([p for p in (eid, *self.chain(eid)) if p in self.places] or [None])[-1]

    def containers_of_class(self, eid, cls):
        return [c for c in reversed(self.chain(eid)) if is_a(self.cls(c), cls)]

    @lru_cache(None)
    def inside(self, holder):
        """Everything kept (transitively) in `holder`, places excluded."""
        return frozenset(e for e in self.by_id if e not in self.places and holder in self.chain(e))

    def subplaces(self, place):
        return frozenset(p for p in self.places if p == place or place in self.chain(p))

    def contents(self, holder, hidden=None, visible_from_above=False):
        """Entities kept in `holder` or in the places below it. `hidden`: a condition on a place that hides what is
        in it from someone who is at the place above; a hidden place shows its contents only when it is the holder
        itself, then together with what is in view at the places above it (`visible_from_above`)."""
        if hidden is None:
            return sorted(self.inside(holder))
        places = {holder}
        frontier = [holder]
        while frontier:
            cur = frontier.pop()
            for p in self.places:
                if self.container(p) == cur and not self.holds(p, hidden):
                    places.add(p)
                    frontier.append(p)
        if visible_from_above and self.holds(holder, hidden):
            up = self.container(holder)
            while up:
                places |= {p for p in self.places if p == up or (self.container(p) == up and not self.holds(p, hidden))}
                up = self.container(up)
        return sorted(e for e in self.by_id if e not in self.places and self.place(e) in places)

    def area(self, place):
        """Places hit by the same area-wide event: the whole tree of the root, and the trees linked by `near`."""
        near_attr = flag(self.cls(place), "near")
        near = {}
        for p in self.places:
            for n in self.ent(p).get(near_attr or "", []):
                near.setdefault(p, set()).add(n)
                near.setdefault(n, set()).add(p)
        out = set(self.subplaces(self.root(place)))
        for member in list(out):
            for n in near.get(member, ()):
                out |= self.subplaces(self.root(n))
        return out

    # ------------------------------------------------------------------ people
    @lru_cache(None)
    def reach(self, pid):
        """Places the person can get to: those that list them (and whose enclosing place they also reach), and themself."""
        def ok(p):
            attr = flag(self.cls(p), "access_by")
            e = self.ent(p)
            return bool(attr) and pid in e.get(attr, []) and (not self.container(p) or ok(self.container(p)))
        return frozenset(p for p in self.places if p == pid or ok(p))

    def reachable_entities(self, pid):
        r = self.reach(pid)
        return [e for e in self.by_id if e not in self.places and self.place(e) in r]

    # ------------------------------------------------------------------ travel
    @lru_cache(None)
    def travel_table(self):
        """Shortest declared travel time in minutes between top-level places; an undeclared pair counts as 0."""
        spec = self.model.get("travel", {})
        roots = {self.root(p) for p in self.places if is_a(self.cls(p), spec.get("between", "Location"))}
        d = {(a, b): 0 for a in roots for b in roots}
        for t in self.data.get("travel_times", []):
            a, b = self.root(t["from"]), self.root(t["to"])
            d[(a, b)] = d[(b, a)] = t["minutes"]
        return d

    def travel(self, a, b):
        return self.travel_table().get((self.root(a), self.root(b)), 0)

    def no_travel(self, place):
        """A place one carries along or reaches from anywhere (memory, cloud): no journey needed."""
        spec = self.model.get("travel", {})
        return not is_a(self.cls(place), spec.get("between", "Location")) or self.holds(place, spec.get("no_travel_when"))

    def journey(self, stops):
        stops = list(stops)
        if len(stops) < 2:
            return 0
        return min(sum(self.travel(a, b) for a, b in zip(p, p[1:])) for p in permutations(stops))

    # ------------------------------------------------------------------ catalogs and attributes
    def catalog_row(self, eid):
        c = self.cls(eid)
        spec = flag(c, "catalog")
        if not spec:
            return None
        key = tuple(str(v[0]) if v else "" for v in (resolve_path(self, self.ent(eid), k) for k in spec["key"]))
        return self.cat.lookup(spec["table"]).get(key)

    def values(self, eid, path, env=None):
        """Values of an attribute path of an entity, for conditions and grouping."""
        return resolve_path(self, eid, path, env)

    def holds(self, eid, expr, env=None):
        """Whether an expression (a condition, a list of conditions, or a combinator) holds for the entity."""
        return evaluate(self, expr, dict(env or {}, **{"$self": eid}))

    def group_key(self, eid, paths):
        return tuple(tuple(sorted(map(str, self.values(eid, p)))) for p in paths)

    # ------------------------------------------------------------------ derived attributes
    def derived(self, cls, attr):
        """Definition of a derived attribute for a class, inherited from its ancestors."""
        while cls:
            d = self.model["derived"].get(f"{cls}.{attr}")
            if d is not None:
                return d
            cls = TABLE.get(cls, {}).get("parent")
        return None

    def derive(self, eid, cls, attr, env=None):
        key = (canon(eid), cls, attr)
        if key in self._derived:
            return self._derived[key]
        d = self.derived(cls, attr)
        if d is None:
            return None
        out = compute_derived(self, eid, cls, d, dict(env or {}))
        if isinstance(eid, str):
            self._derived[key] = out
        return out

    # ------------------------------------------------------------------ dependencies (from the access trees)
    def set_dependencies(self, deps):
        """{entity: set of asset ids whose use depends on it}, computed by the access module."""
        self._deps = deps

    def dependents(self, eid):
        if self._deps is None:
            from access import prepare
            prepare(self)
        return sorted(self._deps.get(eid, ()))


# ---------------------------------------------------------------------- paths

def _step(S, value, key, cls, env):
    """One step of a path on one value; returns (list of values, class of the values if known). A list-valued
    attribute is always a collection; the `[]` suffix of a path only documents that."""
    walk = key.endswith("[]")
    key = key[:-2] if walk else key
    if isinstance(value, str) and value in S.by_id:
        ent_cls = S.cls(value)
        e = S.ent(value)
        if key == "id":
            return [value], None
        if key == "class":
            out, cls = [ent_cls], None
            anc = TABLE.get(ent_cls, {}).get("parent")
            while anc:
                out.append(anc)
                anc = TABLE.get(anc, {}).get("parent")
            return out, None
        if key == "root":
            r = S.root(value) if (value in S.places or S.place(value)) else None
            return ([r] if r else []), None
        if key == "place":
            p = S.place(value)
            return ([p] if p else []), None
        if key == "container":
            c = S.container(value)
            return ([c] if c else []), None
        if key == "catalog":
            row = S.catalog_row(value)
            return ([row] if row else []), "@row"
        if key in e:
            v = e[key]
        else:
            v = S.derive(value, ent_cls, key, env)
            if v is None:
                return [], None
        vals = v if isinstance(v, list) else [v]
        return [x for x in vals if x not in (None, "")], None
    if isinstance(value, dict):
        if key == "*":
            vals = list(value.values())
            return [x for x in vals if x not in (None, "")], None
        if key in value:
            v = value[key]
            vals = v if isinstance(v, list) else [v]
            return [x for x in vals if x not in (None, "")], None
        if cls and cls != "@row":
            v = S.derive(value, cls, key, env)
            if v is not None:
                return (v if isinstance(v, list) else [v]), None
        if len(value) == 1 and isinstance(next(iter(value.values())), str) and next(iter(value.values())) in S.by_id:
            return _step(S, next(iter(value.values())), key + ("[]" if walk else ""), None, env)
        return [], None
    if isinstance(value, list):
        out = []
        for x in value:
            vals, _ = _step(S, x, key + ("[]" if walk else ""), cls, env)
            out.extend(vals)
        return out, None
    return [], None


def resolve_path(S, start, path, env=None):
    """Values of a dotted path from an entity id or a value. `$var` starts at a bound value; `name[]` walks a list;
    `*` takes all values of an object; a reference is followed into the entity it points to; an unknown attribute is
    looked up as a derived attribute. Lists at the end are flattened; empty values are dropped."""
    env = env or {}
    parts = path.split(".")
    cls = None
    if parts[0].startswith("$"):
        name = parts[0]
        if name not in env:
            return []
        cur = env[name]
        cls = env.get("@class", {}).get(name)
        parts = parts[1:]
    else:
        cur = start
    values = cur if isinstance(cur, list) else [cur]
    for part in parts:
        if part == "":
            continue
        nxt, next_cls = [], None
        for v in values:
            vals, cls2 = _step(S, v, part, cls, env)
            nxt.extend(vals)
            next_cls = next_cls or cls2
        values, cls = nxt, next_cls
    out = []
    for v in values:
        if isinstance(v, list):
            out.extend(x for x in v if x not in (None, ""))
        elif v not in (None, ""):
            out.append(v)
    return [canon(v) if isinstance(v, (dict, list)) else v for v in out]


def resolve(S, spec, env):
    """A value in an expression: `$path` is resolved, anything else is a literal."""
    if isinstance(spec, str) and spec.startswith("$"):
        return resolve_path(S, None, spec, env)
    return [spec]


def raw(S, spec, env):
    """Like `resolve`, but objects are returned as they are (for binding nested items such as signers)."""
    if isinstance(spec, str) and spec.startswith("$"):
        parts = spec.split(".")
        cur = env.get(parts[0])
        cls = env.get("@class", {}).get(parts[0])
        values = cur if isinstance(cur, list) else [cur] if cur is not None else []
        for part in parts[1:]:
            nxt = []
            for v in values:
                vals, _ = _step(S, v, part, cls, env)
                nxt.extend(vals)
            values = nxt
            cls = None
        return values
    return [spec]


# ---------------------------------------------------------------------- expressions

def _num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _compare(values, op, target, count):
    if count:
        values = [len(set(map(canon, values)))]
    nums = [n for n in (_num(v) for v in values) if n is not None]
    t = _num(target)
    if t is None:
        return False
    return any({"gt": n > t, "ge": n >= t, "lt": n < t, "le": n <= t}[op] for n in nums)


def condition(S, c, env):
    """One test on an attribute path. Missing values never satisfy `in`, `matches`, `eq`, `contains`, `nonempty`
    or a comparison, and always satisfy `not_in`, `not_matches` and `neq`."""
    self_id = env.get("$self")
    values = resolve_path(S, self_id, c["path"], env)
    count = c.get("count", False)
    if "in" in c:
        return any(v in c["in"] for v in values)
    if "not_in" in c:
        return not any(v in c["not_in"] for v in values)
    if "matches" in c:
        return any(re.search(c["matches"], str(v)) for v in values)
    if "not_matches" in c:
        return not any(re.search(c["not_matches"], str(v)) for v in values)
    if "nonempty" in c:
        return bool(values) == bool(c["nonempty"])
    if "eq" in c:
        targets = resolve(S, c["eq"], env)
        return bool(values) and bool(targets) and any(v in targets for v in values)
    if "neq" in c:
        targets = resolve(S, c["neq"], env)
        return not any(v in targets for v in values)
    if "contains" in c:
        targets = resolve(S, c["contains"], env)
        return bool(targets) and all(t in values for t in targets)
    if "intersects" in c:
        targets = resolve(S, c["intersects"], env)
        return bool(set(values) & set(targets))
    if "disjoint" in c:
        targets = resolve(S, c["disjoint"], env)
        return not set(values) & set(targets)
    for op in ("gt", "ge", "lt", "le"):
        if op in c:
            target = resolve(S, c[op], env)
            return bool(target) and _compare(values, op, target[0], count)
    raise ValueError(f"condition without an operator: {c}")


def _iterate(S, over, env):
    """Items of a quantifier: a class name gives every entity of that class, a path gives its values (objects kept);
    a path without `$` starts at `$self`."""
    if isinstance(over, str) and not over.startswith("$") and over in TABLE:
        return [(x, over) for x in S.ids_of(over)]
    if isinstance(over, str) and not over.startswith("$"):
        over = "$self." + over
    return [(x, None) for x in raw(S, over, env)]


def evaluate(S, expr, env):
    """Boolean value of an expression. Forms: a condition object; a list (all must hold); {"all"/"any": [...]};
    {"not": e}; {"forall"/"exists": over, "as": "$x", "where": e, "class": nested class}; {"can": {...}} (asks the
    access module); a fact name (string) looked up in env["@facts"]. None or [] is true."""
    if expr is None or expr == []:
        return True
    if isinstance(expr, bool):
        return expr
    if isinstance(expr, str):
        facts = env.get("@facts", {})
        if expr.startswith("$"):
            return bool(resolve_path(S, None, expr, env))
        if expr not in facts:
            raise ValueError(f"unknown fact {expr}")
        return bool(facts[expr])
    if isinstance(expr, list):
        return all(evaluate(S, e, env) for e in expr)
    if "all" in expr:
        return all(evaluate(S, e, env) for e in expr["all"])
    if "any" in expr:
        return any(evaluate(S, e, env) for e in expr["any"])
    if "not" in expr:
        return not evaluate(S, expr["not"], env)
    if "forall" in expr or "exists" in expr:
        key = "forall" if "forall" in expr else "exists"
        items = _iterate(S, expr[key], env)
        var = expr["as"]
        results = []
        for item, cls in items:
            sub = dict(env, **{var: item})
            if cls or expr.get("class"):
                sub["@class"] = dict(env.get("@class", {}), **{var: cls or expr["class"]})
            results.append(evaluate(S, expr["where"], sub))
        return all(results) if key == "forall" else any(results)
    if "can" in expr:
        from access import can
        return can(S, expr["can"], env)
    if "path" in expr:
        return condition(S, expr, env)
    raise ValueError(f"unknown expression {expr}")


def compute_derived(S, eid, cls, d, env):
    """A derived attribute. Forms: {"path": p} values of a path; {"select": Class, "as": "$e", "each": p, "item": "$i",
    "where": e, "yield": v} entities (or yielded values) that satisfy a test; {"union": [defs]}; {"containers": Class}
    the enclosing containers of that class, outermost first; {"roots_of": p} outermost places of the entities at p;
    {"reach": true} the places a person reaches; {"dependents": Class, "where": e} assets whose use depends on self;
    {"inside": Class} entities of a class kept in self. `single: true` returns one value instead of a list."""
    env = dict(env, **{"$self": eid})
    if cls:
        env["@class"] = dict(env.get("@class", {}), **{"$self": cls})
    if "union" in d:
        out = []
        for part in d["union"]:
            for v in compute_derived(S, eid, cls, part, env) or []:
                if v not in out:
                    out.append(v)
        result = out
    elif "path" in d:
        result = raw(S, "$self." + d["path"], env) if not d["path"].startswith("$") else raw(S, d["path"], env)
        if "where" in d:
            var = d.get("as", "$x")
            result = [x for x in result if evaluate(S, d["where"], dict(env, **{var: x, "@class": dict(env.get("@class", {}), **{var: d.get("class")})}))]
    elif "select" in d:
        var = d.get("as", "$e")
        result = []
        for e in S.ids_of(d["select"]):
            sub = dict(env, **{var: e})
            if "each" in d:
                ivar = d.get("item", "$i")
                for item in raw(S, var + "." + d["each"], sub):
                    isub = dict(sub, **{ivar: item})
                    if d.get("class"):
                        isub["@class"] = dict(env.get("@class", {}), **{ivar: d["class"]})
                    if evaluate(S, d.get("where"), isub):
                        result.append(_yield(S, d, isub, item))
            elif evaluate(S, d.get("where"), sub):
                result.append(_yield(S, d, sub, e))
    elif "containers" in d:
        result = S.containers_of_class(eid, d["containers"]) if isinstance(eid, str) else []
    elif "roots_of" in d:
        result = []
        for v in raw(S, "$self." + d["roots_of"], env):
            r = S.root(v) if isinstance(v, str) and v in S.by_id else None
            if r and r not in result:
                result.append(r)
    elif "reach" in d:
        result = sorted(S.reach(eid))
    elif "dependents" in d:
        result = [w for w in S.dependents(eid) if is_a(S.cls(w), d["dependents"])]
        if "where" in d:
            var = d.get("as", "$w")
            result = [w for w in result if evaluate(S, d["where"], dict(env, **{var: w}))]
    elif "dependencies" in d:
        from access import deps
        result = sorted(deps(S, eid)) if isinstance(eid, str) else []
    elif "inside" in d:
        result = [e for e in S.contents(eid) if is_a(S.cls(e), d["inside"])]
    elif "value" in d:
        result = [d["value"]]
    else:
        raise ValueError(f"unknown derived attribute form {d}")
    if d.get("single"):
        return result[0] if result else None
    return result


def _yield(S, d, env, default):
    if "yield" not in d:
        return default
    y = d["yield"]
    if isinstance(y, dict):
        return {k: (raw(S, v, env) or [None])[0] for k, v in y.items()}
    return (raw(S, y, env) or [None])[0]


# ---------------------------------------------------------------------- selectors

def select(S, name, target, env=None):
    """Entities an impact selector names, relative to the target. The selectors are defined in AccessModel.json;
    forms: {"self": true}; {"placed_in": p, "hidden": cond, "visible_from_above": bool, "area": bool, "where": cond};
    {"path": p}; {"peers": [paths], "class": C} other entities of the class with the same values."""
    spec = S.model["selectors"].get(name)
    if spec is None:
        raise ValueError(f"impact selector {name} is not defined")
    env = dict(env or {}, **{"$self": target})
    if spec.get("self"):
        return [target]
    if "placed_in" in spec:
        holders = resolve(S, spec["placed_in"], env) if spec["placed_in"].startswith("$") else [spec["placed_in"]]
        out = []
        for h in holders:
            if h not in S.by_id:
                continue
            if spec.get("area"):
                ids = [e for p in S.area(h) for e in S.contents(p)]
            else:
                ids = S.contents(h, spec.get("hidden"), spec.get("visible_from_above", False))
            out.extend(e for e in ids if e not in out)
        if "where" in spec:
            out = [e for e in out if S.holds(e, spec["where"])]
        return sorted(out)
    if "path" in spec:
        return [v for v in resolve_path(S, target, spec["path"], env) if isinstance(v, str) and v in S.by_id]
    if "peers" in spec:
        key = S.group_key(target, spec["peers"])
        cls = spec.get("class", S.cls(target))
        return [e for e in S.ids_of(cls) if e != target and S.group_key(e, spec["peers"]) == key]
    raise ValueError(f"unknown selector form {spec}")
