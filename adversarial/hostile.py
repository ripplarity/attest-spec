import hashlib
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import *

T = tempfile.mkdtemp()


def P(n):
    return os.path.join(T, n)


art = w(P("art"), "hello")
h = hashlib.sha256(b"hello").hexdigest()
art2 = w(P("art2"), "other")
h2 = hashlib.sha256(b"other").hexdigest()
M, C, X = K(), K(), K()
keys = keysfile(P("keys.json"), [M, C])
D = {"sha256": h}
D2 = {"sha256": h2}
S = stmt([D])
_c = [0]


def E(n, o):
    _c[0] += 1
    return w(P("%d_%s" % (_c[0], n)), o)


good = [E("m", env(S, [M])), E("c", env(S, [C]))]

fails = []
res = []


def case(name, r, expect_nonzero=True):
    ok = (r[0] != 0) == expect_nonzero
    res.append((name, r[0]))
    print(("ok  " if ok else "BAD ") + name, "rc", r[0], r[2].strip()[:70])
    if not ok:
        fails.append(name)


case("control_valid_expect0", pol(good, [M.id, C.id], keys, art), False)
case("dup_keyid", pol(good, [M.id, M.id], keys, art))
case(
    "same_key_two_envs",
    pol([E("m1", env(S, [M])), E("m2", env(S, [M]))], [M.id, C.id], keys, art),
)
case(
    "one_env_both_keys(expect accept: envelopes are containers)",
    pol([E("both", env(S, [M, C]))], [M.id, C.id], keys, art),
    False,
)
case(
    "one_env_same_key_twice",
    pol([E("mm", env(S, [M, M]))], [M.id, C.id], keys, art),
)
case(
    "one_env_both_keys_plus_extra_m(same statement: m3's M signature is the one in both -> reuse)",
    pol([E("both", env(S, [M, C])), E("m3", env(S, [M]))], [M.id, C.id], keys, art),
)
case(
    "one_env_both_keys_plus_m_over_other_statement(expect accept)",
    pol(
        [E("both", env(S, [M, C])), E("m4", env(stmt([D], n=2), [M]))],
        [M.id, C.id],
        keys,
        art,
    ),
    False,
)
_b = E("both", env(S, [M, C]))
case("reuse_same_path_twice", pol([_b, _b], [M.id, C.id], keys, art))
case(
    "reuse_byte_copy", pol([_b, w(P("copy"), open(_b).read())], [M.id, C.id], keys, art)
)
_r = json.loads(open(_b).read())
_r["signatures"].reverse()
case("reuse_reordered_sigs", pol([_b, E("rev", _r)], [M.id, C.id], keys, art))
keysX = keysfile(P("keysX.json"), [M, C, X])
case(
    "reuse_plus_extra_sig", pol([_b, E("mx", env(S, [M, X]))], [M.id, C.id], keysX, art)
)
case(
    "unknown_predicate_type_rc5",
    pol(
        [E("m", env(dict(S, predicateType="x"), [M])), E("c", env(S, [C]))],
        [M.id, C.id],
        keys,
        art,
    ),
)
case(
    "mismatched_subjects",
    pol([E("m", env(S, [M])), E("c", env(stmt([D2]), [C]))], [M.id, C.id], keys, art),
)
case("req_absent_from_keyfile", pol(good, [M.id, X.id], keys, art))
case("extra_unrelated_env", pol(good + [E("x", env(S, [X]))], [M.id, C.id], keys, art))
case(
    "extra_env_wrong_digest",
    pol(good + [E("x2", env(stmt([D2]), [M]))], [M.id, C.id], keys, art),
)
sg = env(S, [M])
sg["signatures"] = []
case("zero_sigs", pol([E("m", env(S, [M])), E("z", sg)], [M.id, C.id], keys, art))
case(
    "zero_sigs_only_second",
    pol([E("m", env(S, [M])), E("z", sg)], [M.id, C.id], keys, art),
)
case(
    "keyid_lies",
    pol(
        [E("m", env(S, [M])), E("l", env(S, [C], kidlie=M.id))], [M.id, C.id], keys, art
    ),
)
case(
    "keyid_lies_both_M",
    pol(
        [E("l1", env(S, [C], kidlie=M.id)), E("l2", env(S, [M], kidlie=C.id))],
        [M.id, C.id],
        keys,
        art,
    ),
)
for nm, tf in [
    ("upper_req", lambda s: s.upper()),
    ("ws_req", lambda s: " " + s + "\n"),
]:
    case(nm + " (strict: must reject, rc 2)", pol(good, [tf(M.id), C.id], keys, art))
case(
    "upper_envelope_keyid",
    pol(
        [E("m", env(S, [M])), E("cu", env(S, [C], kidlie=C.id.upper()))],
        [M.id, C.id],
        keys,
        art,
    ),
)
case(
    "ws_envelope_keyid",
    pol(
        [E("m", env(S, [M])), E("cw", env(S, [C], kidlie=C.id + " "))],
        [M.id, C.id],
        keys,
        art,
    ),
)
case(
    "upper_key_digest_in_subject",
    pol(
        [E("m", env(S, [M])), E("cd", env(stmt([{"sha256": h.upper()}]), [C]))],
        [M.id, C.id],
        keys,
        art,
    ),
)
case(
    "payloadType_mismatch",
    pol(
        [E("m", env(S, [M])), E("pt", env(S, [C], ptype="text/plain"))],
        [M.id, C.id],
        keys,
        art,
    ),
)
case(
    "sha512_only",
    pol(
        [
            E("m", env(S, [M])),
            E("s5", env(stmt([{"sha512": hashlib.sha512(b"hello").hexdigest()}]), [C])),
        ],
        [M.id, C.id],
        keys,
        art,
    ),
)
case(
    "sha512_plus_wrong_sha256",
    pol(
        [
            E("m", env(S, [M])),
            E(
                "s6",
                env(
                    stmt(
                        [{"sha256": h2, "sha512": hashlib.sha512(b"hello").hexdigest()}]
                    ),
                    [C],
                ),
            ),
        ],
        [M.id, C.id],
        keys,
        art,
    ),
)
big = stmt(
    [{"sha256": hashlib.sha256(str(i).encode()).hexdigest()} for i in range(20000)]
)
case(
    "huge_subject_list_without_match",
    pol([E("m", env(S, [M])), E("big", env(big, [C]))], [M.id, C.id], keys, art),
)
big2 = stmt([D] * 5000 + [D2] * 5000)
case(
    "dup_subject_list_with_match(expect accept)",
    pol([E("m", env(big2, [M])), E("big2", env(big2, [C]))], [M.id, C.id], keys, art),
    False,
)
case("one_req_only", pol(good, [M.id], keys, art))
case("with_expect_keyid", pol(good, [M.id, C.id], keys, art, ["--expect-keyid", M.id]))
case(
    "no_artifact",
    run(NEW, ["--require-keyid", M.id, "--require-keyid", C.id, "--key", keys] + good),
)
case("wrong_artifact", pol(good, [M.id, C.id], keys, art2))
print("FALSE ACCEPTS / unexpected:", fails)
sys.exit(1 if fails else 0)
