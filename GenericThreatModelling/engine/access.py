"""Access: what an agent (a group of people, or the attacker) can do with a setup in a given state.

The access trees come from the action catalog (RecoveryActions.json): a composite action is `all_of`, `any_of` or
`k_of_n` of its steps, an atomic action has `requires` atoms (reach, intact, known, wait, have). The same tree is
evaluated for the rightful people (strict: parts that are unavailable for now do not count; relaxed: they do), for the
attacker (he reaches what is disclosed or controlled and knows what leaked), walked for the dependencies of a wallet,
cut for the deductive analysis and rendered for the manuals."""
from itertools import combinations

import vocab
from graph import INF, canon, evaluate, flag, raw, resolve, select
from ontology import TABLE, is_a

LEAK = set(vocab.LEAK)
GONE = {"destroyed", "unavailable"}          # a person with one of these is no longer there to act


# ---------------------------------------------------------------- state

class State:
    """Status flags per entity (the impact kinds of the schema), and the people who act against the setup themselves.
    Agents evaluated in the state keep their memo here until the state changes."""

    def __init__(self):
        self.status = {}
        self.actors = set()
        self.agents = {}

    def copy(self):
        n = State()
        n.status = {k: set(v) for k, v in self.status.items()}
        n.actors = set(self.actors)
        return n

    def add(self, eid, kind):
        self.status.setdefault(eid, set()).add(kind)
        self.agents.clear()

    def has(self, eid, *kinds):
        return bool(self.status.get(eid, set()) & set(kinds))

    def affected(self):
        return {e for e, s in self.status.items() if s}

    def summary(self):
        out = {}
        for e, kinds in self.status.items():
            for k in kinds:
                out.setdefault(k, []).append(e)
        return {k: sorted(v) for k, v in sorted(out.items())}


def hit(S, st, eid, kind):
    """One status on one entity; a leak kind is recorded as `disclosed`; what inherits the status of its holder
    (software on a device) gets it too."""
    kind = "disclosed" if kind in LEAK else kind
    st.add(eid, kind)
    for e in S.inside(eid):
        if flag(S.cls(e), "inherits_status") and S.container(e) == eid:
            hit(S, st, e, kind)


def apply_impact(S, st, target, impact):
    """An impact of a threat on its target: the selector names the entities, `only` and `unless` filter them."""
    for e in select(S, impact["on"], target):
        if impact.get("unless") and S.holds(e, impact["unless"]):
            continue
        if impact.get("only") and not S.holds(e, impact["only"]):
            continue
        hit(S, st, e, impact["kind"])


# ---------------------------------------------------------------- agents

class Agent:
    kind = "people"

    def __init__(self, S, st):
        self.S, self.st = S, st
        self.memo = {}

    def reach(self, eid):
        raise NotImplementedError

    def intact(self, eid):
        return True

    def known(self, eid):
        return False

    def bypasses(self, eid):
        return False

    def atom(self, a):
        t = a["type"]
        if t == "have":
            return 0
        if t == "wait":
            return a.get("blocks") or 0
        target = a.get("target")
        if target is None or target not in self.S.by_id:
            return INF
        if t == "reach":
            return 0 if self.reach(target) else INF
        if t == "intact":
            return 0 if self.intact(target) else INF
        if t == "known":
            return 0 if self.known(target) else INF
        raise ValueError(f"unknown atom {t}")


class People(Agent):
    """A group of people (default: everybody who is still there). Strict: unavailable parts count as missing."""

    def __init__(self, S, st, people=None, strict=True):
        super().__init__(S, st)
        actor = S.model["actor"]["class"]
        everyone = S.ids_of(actor)
        self.people = frozenset(p for p in (everyone if people is None else people) if p in everyone and not st.has(p, *GONE))
        self.strict = strict
        self.places = frozenset().union(*[S.reach(p) for p in self.people]) if self.people else frozenset()

    def intact(self, eid):
        bad = ("destroyed", "tampered", "faulty", "unavailable") if self.strict else ("destroyed", "tampered", "faulty")
        return not self.st.has(eid, *bad)

    def reach(self, eid):
        return self.intact(eid) and self.S.place(eid) in self.places


class Place(Agent):
    """Whoever stands at one top-level place and has nothing else: used to ask what one place alone yields."""

    def __init__(self, S, st, place):
        super().__init__(S, st)
        self.root = S.root(place)

    def reach(self, eid):
        p = self.S.place(eid)
        return p is not None and self.S.root(p) == self.root


class Attacker(Agent):
    kind = "attacker"

    def commands(self, eid):
        return self.st.has(eid, "controlled") or (self.st.has(eid, "tampered") and bool(flag(self.S.cls(eid), "active")))

    def reach(self, eid):
        return self.st.has(eid, "disclosed") or self.commands(eid)

    def intact(self, eid):
        """A thing the owners lost may well be in the attacker's hands; information that is gone or wrong is of no use to anybody."""
        return not (flag(self.S.cls(eid), "information") and self.st.has(eid, "destroyed", "faulty"))

    def known(self, eid):
        return self.st.has(eid, "disclosed") and self.intact(eid)

    def bypasses(self, eid):
        return self.commands(eid)


# ---------------------------------------------------------------- trees

def _scalar(values, S=None):
    """One value out of a resolved list; with `S`, a one-key object that wraps a reference ({seed: id}) is the reference."""
    if not values:
        return None
    v = values[0] if len(values) == 1 else values
    return _unwrap(S, v) if S is not None else v


def _unwrap(S, v):
    if isinstance(v, dict) and len(v) == 1 and isinstance(next(iter(v.values())), str) and next(iter(v.values())) in S.by_id:
        return next(iter(v.values()))
    return v


def _bind(S, action, args):
    """Bindings of the parameters: an entity parameter unwraps a reference object, a nested part stays an object."""
    env = {"@class": {}}
    for p in action.get("params", []):
        name = "$" + p["name"]
        if p["name"] in args and args[p["name"]] is not None:
            v = args[p["name"]]
            if not TABLE.get(p["class"], {}).get("nested"):
                v = _unwrap(S, v)
            env[name] = args[p["name"]] = v
            env["@class"][name] = p["class"]
    return env


def _truthy(S, when, env):
    if isinstance(when, str):
        return bool(raw(S, when, env))
    return evaluate(S, when, env)


def tree(S, action_id, args):
    """The access tree of an action with bound arguments. Nodes: action, args, op (all | any | k), k, requires (atoms),
    children, and marks: optional (a step that is not needed for access), guards (the entity whose control makes the
    step unnecessary), cycle, missing (an argument that does not exist). Identical sub-trees (same action, same
    arguments) are shared, so that an evaluation memoised by node covers the whole tree."""
    return _build(S, action_id, args, frozenset())


def _build(S, action_id, args, trail):
    a = S.cat.actions[action_id]
    env = _bind(S, a, args)
    key = (action_id, canon(args))
    cache = S.__dict__.setdefault("_trees", {})
    if key in cache:
        return cache[key]
    node = {"action": action_id, "args": args, "op": {"all_of": "all", "any_of": "any", "k_of_n": "k"}.get(a.get("combinator"), "all"), "children": [], "requires": []}
    if key in trail:
        node["cycle"] = node["has_cycle"] = True
        return node
    for p in a.get("params", []):
        if p["name"] not in args or args[p["name"]] is None:
            node["missing"] = p["name"]
            return node
    for r in a.get("requires", []):
        atom = {"type": r["type"]}
        if "target" in r:
            atom["target"] = _scalar(raw(S, r["target"], env), S) if isinstance(r["target"], str) and r["target"].startswith("$") else r["target"]
        if "blocks" in r:
            v = _scalar(resolve(S, r["blocks"], env))
            atom["blocks"] = v if isinstance(v, (int, float)) else 0
        if "what" in r:
            atom["what"] = r["what"]
        node["requires"].append(atom)
    if node["op"] == "k":
        k = _scalar(resolve(S, a["k"], env))
        node["k"] = int(k) if isinstance(k, (int, float)) else None
    for step in a.get("steps", []):
        for sub in _expand(S, step, env):
            if "when" in step and not _truthy(S, step["when"], sub):
                continue
            child_args = {}
            for name, spec in step.get("args", {}).items():
                child_args[name] = _scalar(raw(S, spec, sub)) if isinstance(spec, str) and spec.startswith("$") else spec
            child = _build(S, step["action"], child_args, trail | {key})
            if step.get("optional"):
                child = dict(child, optional=True)
            if "guards" in step:
                g = _scalar(raw(S, step["guards"], sub), S)
                if isinstance(g, str):
                    child = dict(child, guards=g)
            node["children"].append(child)
            if child.get("has_cycle"):
                node["has_cycle"] = True
    if not node.get("has_cycle"):
        cache[key] = node
    return node


def _expand(S, step, env):
    fe = step.get("foreach")
    if not fe:
        return [env]
    items = raw(S, fe["over"], env)
    out = []
    for item in items:
        sub = dict(env, **{"$" + fe["as"]: item})
        sub["@class"] = dict(env["@class"])
        if "class" in fe:
            sub["@class"]["$" + fe["as"]] = fe["class"]
        out.append(sub)
    return out


def people(S, st, people=None, strict=True):
    """The agent for a group of people in a state, with its memo kept on the state."""
    key = ("people", None if people is None else frozenset(people), strict)
    if key not in st.agents:
        st.agents[key] = People(S, st, people, strict)
    return st.agents[key]


def attacker(S, st):
    if "attacker" not in st.agents:
        st.agents["attacker"] = Attacker(S, st)
    return st.agents["attacker"]


def flat(node):
    """The nodes of a tree in post-order, each once (identical sub-trees are shared), for an iterative evaluation."""
    if "_flat" in node:
        return node["_flat"]
    order, seen = [], set()

    def visit(n):
        if id(n) in seen:
            return
        seen.add(id(n))
        for c in n["children"]:
            visit(c)
        order.append(n)
    visit(node)
    node["_flat"] = order
    return order


def value(node, agent, memo=None):
    """Least delay (blocks) with which the agent completes the action; INF if it cannot."""
    memo = agent.memo if memo is None else memo
    if id(node) in memo:
        return memo[id(node)]
    atom, bypasses = agent.atom, agent.bypasses
    for n in flat(node):
        key = id(n)
        if key in memo:
            continue
        if n.get("cycle") or n.get("missing"):
            memo[key] = INF
            continue
        out = 0
        for a in n["requires"]:
            v = atom(a)
            if v > out:
                out = v
        kids = [0 if (c.get("guards") and bypasses(c["guards"])) else memo[id(c)] for c in n["children"] if not c.get("optional")]
        op = n["op"]
        if op == "all":
            for v in kids:
                if v > out:
                    out = v
        elif op == "any":
            best = min(kids, default=INF)
            out = best if best > out else out
        else:
            k = n.get("k")
            if k is None or k < 1 or len(kids) < k:
                out = INF
            else:
                kids.sort()
                out = max(out, kids[k - 1])
        memo[key] = out
    return memo[id(node)]


def profile(node, agent, memo=None, out=None):
    """How many children of every choice node the agent can complete: the redundancy left in the tree."""
    memo = agent.memo if memo is None else memo
    out = [] if out is None else out
    if node.get("cycle") or node.get("missing"):
        return out
    if node["op"] in ("any", "k"):
        out.append(sum(1 for c in node["children"] if not c.get("optional") and (c.get("guards") and agent.bypasses(c["guards"]) or value(c, agent, memo) < INF)))
    for c in node["children"]:
        profile(c, agent, memo, out)
    return out


def entities(S, node, out=None, optional=True):
    """Every entity the tree touches: atom targets with the containers they sit in or run on (not the places),
    guards and entity-valued arguments."""
    out = set() if out is None else out
    for a in node["requires"]:
        if isinstance(a.get("target"), str):
            out.add(a["target"])
            out.update(c for c in S.chain(a["target"]) if c not in S.places)
    if node.get("guards"):
        out.add(node["guards"])
    for v in node["args"].values():
        for x in (v if isinstance(v, list) else [v]):
            if isinstance(x, str):
                out.add(x)
    for c in node["children"]:
        if optional or not c.get("optional"):
            entities(S, c, out, optional)
    return out


# ---------------------------------------------------------------- goals of the setup

def goal(S, name, **args):
    g = S.model["goals"][name]
    if "param" in g:
        return tree(S, g["action"], {g["param"]: args[g["param"]]})
    return tree(S, g["action"], {k: args[v[1:]] for k, v in g["params"].items()})


def spend_tree(S, wid, policy=None):
    if policy is None:
        return goal(S, "spend", wallet=wid)
    pol = S.ent(wid)[S.model["asset"]["policies"][:-2]][policy]
    return goal(S, "policy", wallet=wid, policy=pol)


def _slice(S, st, wid):
    """The part of a state the wallet's tree can see: statuses of its dependencies and of the people."""
    d = deps(S, wid)
    actor = S.model["actor"]["class"]
    return frozenset((e, k) for e, ks in st.status.items() if e in d or is_a(S.cls(e), actor) for k in ks)


def spend_delay(S, st, wid, people_=None, strict=True):
    cache = S.__dict__.setdefault("_eval_cache", {})
    key = ("spend", wid, None if people_ is None else frozenset(people_), strict, _slice(S, st, wid))
    if key not in cache:
        cache[key] = value(spend_tree(S, wid), people(S, st, people_, strict))
    return cache[key]


def theft_delay(S, st, wid):
    """Least delay with which the attacker spends the wallet with what the state gives him; None if he cannot."""
    cache = S.__dict__.setdefault("_eval_cache", {})
    key = ("theft", wid, _slice(S, st, wid))
    if key not in cache:
        d = value(spend_tree(S, wid), attacker(S, st))
        cache[key] = None if d == INF else d
    return cache[key]


def knows(S, st, eid):
    """The attacker knows a secret (or the plan), directly or through what he reaches."""
    return value(goal(S, "know", secret=eid), attacker(S, st)) < INF


def attacker_secrets(S, st):
    """Every secret and plan copy the attacker can obtain in the state."""
    out = set()
    for eid, (c, _) in S.by_id.items():
        if (is_a(c, "Secret") or flag(c, "singleton")) and knows(S, st, eid):
            out.add(eid)
    return out


def descriptor_known(S, st, wid):
    return value(goal(S, "descriptor", wallet=wid), attacker(S, st)) < INF


def tier(S, st, wid):
    """0 usable now, 1 only after a delay or a repair, 2 no way left."""
    strict = spend_delay(S, st, wid, strict=True)
    if strict == 0:
        return 0
    if strict < INF or spend_delay(S, st, wid, strict=False) < INF:
        return 1
    return 2


def prepare(S):
    """Dependencies of every asset on every entity, from the access trees; needed before `dependents` is used."""
    deps = {}
    for w in S.ids_of(S.model["asset"]["class"]):
        for e in entities(S, spend_tree(S, w)) | {w}:
            deps.setdefault(e, set()).add(w)
    S.set_dependencies(deps)


def deps(S, wid, policy=None):
    """Everything the wallet's use depends on, with `policy` (0-based) only what that spending policy needs."""
    cache = S.__dict__.setdefault("_deps_cache", {})
    if (wid, policy) not in cache:
        cache[(wid, policy)] = frozenset(entities(S, spend_tree(S, wid, policy)) | {wid})
    return cache[(wid, policy)]


def can(S, spec, env):
    """An expression asks whether an agent completes an action: {"agent": "everyone" | "attacker" | {"person": p} |
    {"place": l}, "action": id, "args": {name: value}, "strict": bool}."""
    st = env.get("@state") or State()
    who = spec.get("agent", "everyone")
    if who == "attacker":
        agent = attacker(S, st)
    elif who == "everyone":
        agent = people(S, st, None, spec.get("strict", False))
    elif "person" in who:
        p = _scalar(resolve(S, who["person"], env))
        agent = people(S, st, [p] if isinstance(p, str) else [], spec.get("strict", False))
    elif "place" in who:
        p = _scalar(resolve(S, who["place"], env))
        if not isinstance(p, str):
            return False
        agent = Place(S, st, p)
    else:
        raise ValueError(f"unknown agent {who}")
    args = {k: _scalar(raw(S, v, env)) if isinstance(v, str) and v.startswith("$") else v for k, v in spec.get("args", {}).items()}
    if any(v is None for v in args.values()):
        return False
    return value(tree(S, spec["action"], args), agent) < INF


# ---------------------------------------------------------------- deductive analysis: cut sets and path sets

def _minimal(sets):
    sets = sorted({frozenset(s) for s in sets}, key=lambda s: (len(s), sorted(s)))
    out = []
    for s in sets:
        if not any(o <= s for o in out):
            out.append(s)
    return out


def _product(lists, limit):
    out = [frozenset()]
    for alts in lists:
        out = _minimal(a | b for a in out for b in alts)[:limit]
        if not out:
            return []
    return out


def failure_sets(node, atoms_of, limit=200):
    """Minimal sets of events after which the action can no longer be completed. `atoms_of(node)` names the
    events that stop an atomic node (one failure event per entity). Composite: all_of fails if any step fails
    (union), any_of if every step fails (product), k_of_n if n-k+1 steps fail."""
    if node.get("cycle") or node.get("missing"):
        return []                       # already impossible: nothing to fail
    own = [frozenset([e]) for e in atoms_of(node)]
    kids = [failure_sets(c, atoms_of, limit) for c in node["children"] if not c.get("optional")]
    kids = [k for k in kids]
    if node["op"] == "all":
        sets = own + [s for k in kids for s in k]
    elif node["op"] == "any":
        sets = own + (_product(kids, limit) if kids else [])
    else:
        k = node.get("k") or 1
        n = len(kids)
        need = n - k + 1
        sets = list(own)
        if 0 < need <= n:
            for combo in combinations(range(n), need):
                sets += _product([kids[i] for i in combo], limit)
    return _minimal(sets)[:limit]


def success_sets(node, atoms_of, agent_free, limit=200):
    """Minimal sets of events that let the action be completed. `atoms_of(node)` names the events that satisfy an
    atomic node; `agent_free(node)` says the node is satisfied without any event (tools, waiting)."""
    if node.get("cycle") or node.get("missing"):
        return []
    own = atoms_of(node)
    kids = [c for c in node["children"] if not c.get("optional")]
    kid_sets = [success_sets(c, atoms_of, agent_free, limit) for c in kids]
    if node["op"] == "all":
        parts = ([own] if own else []) + kid_sets
        return _product(parts, limit) if parts else [frozenset()]
    if node["op"] == "any":
        sets = list(own) + [s for k in kid_sets for s in k]
        return _minimal(sets)[:limit]
    k = node.get("k") or 1
    sets = []
    for combo in combinations(range(len(kids)), k):
        sets += _product([kid_sets[i] for i in combo] + ([own] if own else []), limit)
    return _minimal(sets)[:limit]
