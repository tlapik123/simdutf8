from z3 import *

num_states = 9

# unique state->state transitions for all characters
transitions = [
 # (0, 8, 8, 8, 8, 8, 8, 8, 8),
 # (1, 8, 8, 8, 8, 8, 8, 8, 8),
 # (2, 8, 8, 8, 8, 8, 8, 8, 8),
 # (3, 8, 8, 8, 8, 8, 8, 8, 8),
 # (4, 8, 8, 8, 8, 8, 8, 8, 8),
 # (5, 8, 8, 8, 8, 8, 8, 8, 8),
 # (6, 8, 8, 8, 8, 8, 8, 8, 8),
 # (7, 8, 8, 8, 8, 8, 8, 8, 8),
 # (8, 0, 1, 1, 8, 2, 2, 8, 8),
 # (8, 0, 1, 8, 1, 2, 2, 8, 8),
 # (8, 0, 1, 8, 1, 2, 8, 2, 8),
 # (8, 8, 8, 8, 8, 8, 8, 8, 8)
[0, 8, 8, 8, 8, 8, 8, 8, 8],
[8, 0, 8, 1, 1, 8, 3, 3, 8],
[8, 0, 8, 1, 1, 3, 3, 8, 8],
[8, 0, 1, 1, 8, 3, 3, 8, 8],
[1, 8, 8, 8, 8, 8, 8, 8, 8],
[2, 8, 8, 8, 8, 8, 8, 8, 8],
[3, 8, 8, 8, 8, 8, 8, 8, 8],
[4, 8, 8, 8, 8, 8, 8, 8, 8],
[5, 8, 8, 8, 8, 8, 8, 8, 8],
[6, 8, 8, 8, 8, 8, 8, 8, 8],
[7, 8, 8, 8, 8, 8, 8, 8, 8],
[8, 8, 8, 8, 8, 8, 8, 8, 8],
]

s = Solver()

offsets = [BitVec('o%d' % i, 32) for i in range(num_states)]
values = [BitVec('v%d' % i, 32) for i in range(len(transitions))]

# these weren't necessary, but gave slightly nicer numbers
# for v in values:
#     s.add(v >> 30 == -1)
# s.add(offsets[0] == 0)
# s.add(offsets[8] == 0)
s.add(offsets[0] == 8)

for i in range(len(offsets)):
    s.add(offsets[i] < 32)
    for j in range(i+1, len(offsets)):
        s.add(offsets[i] != offsets[j])

for vn, targets in enumerate(sorted(transitions)):
    for off, target in enumerate(targets):
        s.add((RotateRight(values[vn], offsets[off]) & 31) == offsets[target])
        s.add(((values[vn] >> offsets[off]) & 31) == offsets[target])

print(s.check())

offsets = [s.model()[i].as_long() for i in offsets]
print('offsets:', offsets)

values = [s.model()[i].as_long() for i in values]

print('transitions:')
for t, v in zip(transitions, values):
    print(t, format(v, '032b'), hex(v))

# def to_signed(val, bits=32):
#     if (val & (1 << (bits - 1))) != 0:
#         val = val - (1 << bits)
#     return val

# def all_smt(s, initial_terms):
#     def block_term(s, m, t):
#         s.add(t != m.eval(t))
#     def fix_term(s, m, t):
#         s.add(t == m.eval(t))
#     def all_smt_rec(terms):
#         if sat == s.check():
#            m = s.model()
#            yield m
#            for i in range(len(terms)):
#                s.push()
#                block_term(s, m, terms[i])
#                for j in range(i):
#                    fix_term(s, m, terms[j])
#                yield from all_smt_rec(terms[i:])
#                s.pop()
#     yield from all_smt_rec(list(initial_terms))

# def hex32(n):
#     return '0x{0:0{1}x}'.format(n, 8)

# if s.check() != sat:
#     print("not sat :(")
# else:
#     for model_index, model in enumerate(all_smt(s, offsets+values)):
#         print("Model", model_index)
#         offs = [model[oi].as_long() for oi in offsets]
#         print("  offsets:", offs)
#         for o in offs:
#             print('   ', format(o, '05b'), o)
#         vals = [model[vi].as_long() for vi in values]
#         print('  transitions:')
#         for v in vals:
#             print('   ', format(v, '032b'), hex32(v), to_signed(v))

#         sys.stdout.flush()
