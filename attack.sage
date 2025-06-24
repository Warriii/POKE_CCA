import os

from montgomery_isogenies.kummer_line import KummerLine
from montgomery_isogenies.kummer_isogeny import KummerLineIsogeny

from utilities.discrete_log import BiDLP
from utilities.supersingular import torsion_basis

from POKE_PKE_modified import *

"""
Initialise Params
"""
bs = [162, 243, 324]
i, lambda_ = 0, 128
a = lambda_ - 2
b = bs[i]
c = floor(lambda_/3 * log(2)/log(5))
A = Integer(2**a)
B = Integer(3**b)
assert B > 2**(2 * lambda_)
C = 5**c
p = make_prime(4*A*B*C)

x = C

a = factor(p+1)[0][1] - 2
A = Integer(2**a)



FF.<xx> = GF(p)[]
F.<i> = GF(p^2, modulus=xx^2+1)
E0 = EllipticCurve(F, [1, 0])
E0.set_order((p+1)**2)
PA, QA = torsion_basis(E0, 4*A)
PB, QB = torsion_basis(E0, B)
X0, Y0 = torsion_basis(E0, C)

PQA = PA - QA
PQB = PB - QB
XY0 = X0 - Y0

_E0 = KummerLine(E0)
_PB = _E0(PB[0])
_QB = _E0(QB[0])
_PQB = _E0(PQB[0])

xPA = _E0(PA[0])
xQA = _E0(QA[0])
xPQA = _E0(PQA[0])

xX_0 = _E0(X0[0])
xY_0 = _E0(Y0[0])
xXY_0 = _E0(XY0[0])

"""
===========
Our Attack
===========
"""
from tqdm import trange

# Helper Functions
def base3(x):
    res = ""
    while x:
        res = str(x % 3) + res
        x//=3
    return res

def kummer_isogeny(phi, xP, xQ, xPQ):
    ximP, ximQ, ximPQ = phi(xP), phi(xQ), phi(xPQ)
    PP, QQ = ximP.curve_point(), ximQ.curve_point()
    if (PP - QQ)[0] != ximPQ.x():
        QQ = -QQ
    return PP, QQ

# User class with improper implementation of POKE
class User:
    def __init__(self, isAlice, debug=False):
        if isAlice: # user plays the role of Alice in the key exchange
            self._priv, self.pub = keygenA()
        else: # user plays the role of Bob
            self._priv = random_unit(B)
            self.pub = [] # Per implementation, public data is only obtained from encrypt() call.
            if debug:
                print(f"[BOB] {base3(self._priv)}")
        self.isAlice = isAlice
    
    def getPub(self):
        return self.pub
    
    def encrypt_msg(self, User, m=b"Test Message"):
        if self.isAlice: # does not apply
            return []
        vals = encrypt(User.getPub(), m, self._priv)
        self.pub = vals[:5] # EB, P2_B, Q2_B, X_B, Y_B 
        return vals
    
    def decrypt_msg(self, ct):
        if not self.isAlice:
            return []
        return decrypt(self._priv, ct)

# Oracle in question
def oracle(Alice, Bob):
    return Bob.encrypt_msg(Alice)

# Simulate Attack
Alice, Bob = User(True), User(False, True)
Charlie = User(True)

aa, bb, cc, xP3, xQ3, xPQ3, dd, ee = Alice.getPub()
AP3, AQ3, APQ3 = xP3.curve_point(), xQ3.curve_point(), xPQ3.curve_point()
if (AP3 - AQ3)[0] != APQ3.x():
    AQ3 = -AQ3
AEA = KummerLine(AP3.curve())

# Recover Bob's r_3 value
rr = 0
for ii in trange(b):
    success = False
    for r in range(3):
        AP3_ = AP3 - rr * 3**(b-1-ii) * AQ3 - r * 3**(b-1) * AQ3
        AQ3_ = AQ3 + 3**(b-1-ii) * AQ3
        xP3_, xQ3_, xPQ3_ = AEA(AP3_[0]), AEA(AQ3_[0]), AEA((AP3_-AQ3_)[0])
        pkA_ = (aa, bb, cc, xP3_, xQ3_, xPQ3_, dd, ee)

        # modify pub values for oracle, then reset them
        Alice.pub = pkA_
        ctB = oracle(Alice, Bob)
        Alice.pub = (aa, bb, cc, xP3, xQ3, xPQ3, dd, ee)

        try:
            pt = Alice.decrypt_msg(ctB) # errors because "Not a product of elliptic curves"
            success = True
            rr += 3**ii * r
            # print("A", base3(rr))
            # print("B", base3(Bob._priv)[-len(base3(rr)):])
            assert pt == b"Test Message"
            break
        except ValueError as err:          # Not a product of elliptic curves
            continue
    assert success
print(f"Recovered base3(rr) = {base3(rr)}") # as malicious Alice, we've leaked r!

# Recover Bob's isogeny psi
_KB = _QB.ladder_3_pt(_PB, _PQB, rr)
psi = KummerLineIsogeny(_E0, _KB, B)

# Charlie and Bob begin communicating. WLOG let Bob send encrypted ciphertext to Charlie with sesh key
m = os.urandom(128)
C_EB, C_P2_B, C_Q2_B, C_X_B, C_Y_B, C_EAB, C_P2_AB, C_Q2_AB, C_ct = Bob.encrypt_msg(Charlie, m)

# As Alice we recover D5_BC
xP2_B, xQ2_B = psi(xPA), psi(xQA)
X_B, Y_B = kummer_isogeny(psi, xX_0, xY_0, xXY_0)
dd1, dd2 = BiDLP(C_X_B, X_B, Y_B, 5**c)
dd3, dd4 = BiDLP(C_Y_B, X_B, Y_B, 5**c)

# And then from Charlie's public key, recover the message!
CxP2, CxQ2, CxPQ2, CxP3, CxQ3, CxPQ3, CX_A, CY_A = Charlie.getPub()
EA = CxP3.parent()
CxK = CxQ3.ladder_3_pt(CxP3, CxPQ3, rr)
phiB_ = KummerLineIsogeny(EA, CxK, B)
CxX_A, CxY_A, CxXY_A = EA(CX_A[0]), EA(CY_A[0]), EA((CX_A-CY_A)[0])
CX_AB, CY_AB = kummer_isogeny(phiB_, CxX_A, CxY_A, CxXY_A)
CX_AB, CY_AB = dd1*CX_AB + dd2*CY_AB, dd3*CX_AB + dd4*CY_AB
xof = xof_kdf(CX_AB[0], CY_AB[0])
rec_m = xof_encrypt(xof, C_ct)
assert rec_m == m

print(f"Decrypted Charlie msg: {rec_m.hex()[:40]}...")
print(f"          Charlie msg: {m.hex()[:40]}...")