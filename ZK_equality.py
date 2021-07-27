from zksk import Secret, DLRep
from zksk import utils

def ZK_equality(G,H):
    r_1 = Secret(utils.get_random_num(bits=128))
    print(r_1)
    r2 = Secret(utils.get_random_num(bits=128))
    print
    m = Secret(utils.get_random_num(bits=128))

    #Generate two El-Gamal ciphertexts (C1,C2) and (D1,D2)
    C1, C2 = elgamal(G, H, r_1, m)
    D1, D2 = elgamal(G, H, r2, m)

    #Generate a NIZK proving equality of the plaintexts
    #Define statement
    statment = DLRep(C1, r_1*G) & DLRep(C2, r_1*H+m*G) & DLRep(D1, r2*G) & DLRep(D2, r2*H+m*G)

    zk_proof = statment.prove()

    #Return two ciphertexts and the proof
    return (C1,C2), (D1,D2), zk_proof

def elgamal(G, H, r, m):
    x = r.value * G
    y = r.value * H + m.value * G
    return x,y