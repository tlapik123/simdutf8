# pack UTF-8 shift-based DFA into 32-bit integers
#
# based on work by Dougall Johnson:
# https://gist.github.com/dougallj/166e326de6ad4cf2c94be97a204c025f

from z3 import *
import sys

num_states = 9

transitions = [
    (0,  0,  0,  0,  0,  0,  0,  0,  0),
    (0,  1,  0,  0,  0,  0,  0,  0,  0),
    (0,  2,  0,  0,  0,  0,  0,  0,  0),
    (0,  3,  0,  0,  0,  0,  0,  0,  0),
    (0,  4,  0,  0,  0,  0,  0,  0,  0),
    (0,  5,  0,  0,  0,  0,  0,  0,  0),
    (0,  6,  0,  0,  0,  0,  0,  0,  0),
    (0,  7,  0,  0,  0,  0,  0,  0,  0),
    (0,  8,  0,  0,  0,  0,  0,  0,  0),
    (0,  0,  1,  2,  3,  0,  2,  0,  3),
    (0,  0,  1,  2,  3,  0,  2,  3,  0),
    (0,  0,  1,  2,  3,  2,  0,  3,  0)
]

s = Solver()
offsets = [BitVec('o%d' % i, 32) for i in range(num_states)]
values  = [BitVec('v%d' % i, 32) for i in range(len(transitions))]

for i in range(len(offsets)):
    s.add(offsets[i] < 32)
    for j in range(i+1, len(offsets)):
        s.add(offsets[i] != offsets[j])

for vn, targets in enumerate((transitions)):
    for off, target in enumerate(targets):
        s.add(((values[vn] >> offsets[off]) & 31) == offsets[target])

def to_signed(val, bits=32):
    if (val & (1 << (bits - 1))) != 0:
        val = val - (1 << bits)
    return val

# avoid sign extension
for v in values[1:]:
    s.add(v > 0)

s.add(values[0] == 0)
for vlead in values[1:9]:
    s.add(vlead & (31 << offsets[1]) == vlead)
s.add(values[9]  == (offsets[1] << offsets[2]) | (offsets[2] << offsets[3]) | \
    (offsets[3] << offsets[4]) | (offsets[2] << offsets[6]) | (offsets[3] << offsets[8]))
s.add(values[10] == (offsets[1] << offsets[2]) | (offsets[2] << offsets[3]) | \
    (offsets[3] << offsets[4]) | (offsets[2] << offsets[6]) | (offsets[3] << offsets[7]))
s.add(values[11] == (offsets[1] << offsets[2]) | (offsets[2] << offsets[3]) | \
    (offsets[3] << offsets[4]) | (offsets[2] << offsets[5]) | (offsets[3] << offsets[7]))

# force `(state & 0xf) == 0` as a fast way to check `state == err || state == end` (optional)
s.add(offsets[0] == 0)
s.add(offsets[1] == 16)
for o in offsets[2:]:
    s.add((o % 16) != 0)

def all_smt(s, initial_terms):
    def block_term(s, m, t):
        s.add(t != m.eval(t))
    def fix_term(s, m, t):
        s.add(t == m.eval(t))
    def all_smt_rec(terms):
        if sat == s.check():
           m = s.model()
           yield m
           for i in range(len(terms)):
               s.push()
               block_term(s, m, terms[i])
               for j in range(i):
                   fix_term(s, m, terms[j])
               yield from all_smt_rec(terms[i:])
               s.pop()
    yield from all_smt_rec(list(initial_terms))

def hex32(n):
    return '0x{0:0{1}x}'.format(n, 8)

if s.check() != sat:
    print("not sat :(")
else:
    for model_index, model in enumerate(all_smt(s, offsets+values)):
        print("Model", model_index)
        offs = [model[oi].as_long() for oi in offsets]
        print("  offsets:", offs)
        for o in offs:
            print('   ', format(o, '05b'), o)
        vals = [model[vi].as_long() for vi in values]
        print('  transitions:')
        for v in vals:
            print('   ', format(v, '032b'), hex32(v), to_signed(v))

        sys.stdout.flush()
