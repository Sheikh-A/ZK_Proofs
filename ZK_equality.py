from zksk import Secret, DLRep
from zksk import utils

def ZK_equality(G,H):
    r_1 = Secret(utils.get_random_num(bits=128))
    print(r_1)
    r_2 = Secret(utils.get_random_num(bits=128))
    print(r_2)
    m = Secret(utils.get_random_num(bits=128))
    print(m)

    #Generate two El-Gamal ciphertexts (C1,C2) and (D1,D2)
    C1, C2 = elgamal(G, H, r_1, m)
    D1, D2 = elgamal(G, H, r_2, m)

    #Generate a NIZK proving equality of the plaintexts
    #Define statement
    statment = DLRep(C1, G * r_1) & DLRep(C2, r_1 * H + m * G) & DLRep(D1, G * r_2) & DLRep(D2, r_2*H+m*G)
    #Proof
    #print(statement)
    zk_proof = statment.prove()

    #Return two ciphertexts and the proof
    return (C1,C2), (D1,D2), zk_proof

def elgamal(G, H, r, m):
    #define x
    x =  r.value * G
    #print(x)
    y = r.value * H + m.value * G
    #print(y)
    return x,y