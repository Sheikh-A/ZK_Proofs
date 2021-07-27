from zksk import Secret, DLRep
from zksk import utils

def ZK_equality(G,H):
    sec = Secret(utils.get_random_num(bits=128))
    r_1 = Secret(utils.get_random_num(bits=128))
    r_2 = Secret(utils.get_random_num(bits=128))

    #Generate two El-Gamal ciphertexts (C1,C2) and (D1,D2)
    #USE C1,C2 here
    C1, C2 = elgamal(G, H, r_1, sec)
    # print(C1)
    # print(C2)
    #D1 D2 go here
    D1, D2 = elgamal(G, H, r_2, sec)

    #Generate a NIZK proving equality of the plaintexts
    statement = DLRep(C1, r_1*G) and DLRep(C2, r_1*H+sec*G) and DLRep(D1, r_2*G) and DLRep(D2, r_2*H+sec*G)
    print(statement)
    #zk_proof
    zk_proof = statement.prove()

    #Return two ciphertexts and the proof
    return (C1,C2), (D1,D2), zk_proof

def elgamal(G, H, r, m):
    #EL GAMAL
    x = r.value * G
    #Y value
    y = r.value * H + m.value * G
    #return value
    return x,y