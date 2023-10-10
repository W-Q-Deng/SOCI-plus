import random

import gmpy2

from paillier_third_party import *
import paillier_NewOpt


def sec_mul(e_x, e_y, tuple_S_0: dict, tuple_S_1: dict, S_0: Paillier_Third_party, S_1: Paillier_Third_party):
    '''
    the protocol of SMUL
    return the encrypted result of x * y
    :param e_x: Encrypted data x
    :param e_y: Encrypted data y
    :param tuple_S_0: Tuple for pre-computation of S_0
    :param S_0:  Cloud Platform (S_0)
    :param S_1:Computation Service Provider (S_1)
    :return:
    '''
    public_key = S_0.public_key
    N = public_key['N']
    N_square = N ** 2
    L = public_key['L']

    # step 1, S_0
    r1, r2, e_r1, e_r2, e_negative_r1_r2 = tuple_S_0['r_1'], tuple_S_0['r_2'], tuple_S_0['e_r_1'], tuple_S_0['e_r_2'], \
                                           tuple_S_0[
                                               'e_negative_r1_r2']
    # refreshing ciphertext
    tuple_S_0['e_r_1'] = gmpy2.mod(gmpy2.mul(tuple_S_0['e_r_1'], tuple_S_0['e_0']), N_square)
    tuple_S_0['e_r_2'] = gmpy2.mod(gmpy2.mul(tuple_S_0['e_r_2'], tuple_S_0['e_0']), N_square)
    tuple_S_0['e_negative_r1_r2'] = gmpy2.mod(gmpy2.mul(tuple_S_0['e_negative_r1_r2'], tuple_S_0['e_0']), N_square)

    X = gmpy2.mod(gmpy2.mul(e_x, e_r1), N_square)
    Y = gmpy2.mod(gmpy2.mul(e_y, e_r2), N_square)
    C = gmpy2.mod(gmpy2.mul(gmpy2.powmod(X, L, N_square), Y), N_square)
    C1 = paillier_NewOpt.PDec(partial_private_key=S_0.private_partial_key, ciphertext=C)

    '''
    send (C,C1) to S_1 
    '''

    # step2, S_1
    C2 = paillier_NewOpt.PDec(partial_private_key=S_1.private_partial_key, ciphertext=C)
    Lmulxaddr1_yaddr2 = paillier_NewOpt.TDec(C1, C2, N)
    xaddr1 = Lmulxaddr1_yaddr2 // L
    yaddr2 = Lmulxaddr1_yaddr2 % L
    e_xaddr1_mul_yaddr2 = paillier_NewOpt.Enc_NewOpt(public_key, gmpy2.mod(gmpy2.mul(xaddr1, yaddr2), N))

    '''
    send e_xaddr1_mul_yaddr2 to S_0
    '''

    # step3, S_0
    e_negative_r2x = gmpy2.powmod(e_x, -r2, N_square)
    e_negative_r1y = gmpy2.powmod(e_y, -r1, N_square)
    e_xy = gmpy2.mod(gmpy2.mul(
        gmpy2.mod(gmpy2.mul(gmpy2.mod(gmpy2.mul(e_xaddr1_mul_yaddr2, e_negative_r2x), N_square), e_negative_r1y),
                  N_square), e_negative_r1_r2), N_square)
    return e_xy


def sec_cmp(e_x, e_y, tuple_S_0: dict, tuple_S_1: dict, S_0: Paillier_Third_party, S_1: Paillier_Third_party):
    '''
    the protocol of SCMP
    Comparison result of x and y returned in encrypted form
    :param e_x: Encrypted data x
    :param e_y: Encrypted data y
    :param tuple_S_0: Tuple for pre-computation of S_0
    :param tuple_S_1: Tuple for pre-computation of S_1
    :param S_0:  Cloud Platform (S_0)
    :param S_1:Computation Service Provider (S_1)
    :return:Returns an encrypted u, if x>=y, then u equals 0; Otherwise, u=1
    '''
    public_key = S_0.public_key
    N = public_key['N']
    N_square = N ** 2

    pi = random.randint(0, 1)

    # step 1,S_0
    r_1, r_2, e_r1_add_r2, e_r2 = tuple_S_0['r_3'], tuple_S_0['r_4'], tuple_S_0['e_r3_add_r4'], tuple_S_0['e_r_4']
    # refreshing ciphertext
    tuple_S_0['e_r3_add_r4'] = gmpy2.mod(gmpy2.mul(tuple_S_0['e_r3_add_r4'], tuple_S_0['e_0']), N_square)
    tuple_S_0['e_r_4'] = gmpy2.mod(gmpy2.mul(tuple_S_0['e_r_4'], tuple_S_0['e_0']), N_square)

    if pi == 0:
        D = gmpy2.mod(
            gmpy2.mul(
                gmpy2.powmod(gmpy2.mod(gmpy2.mul(e_x, gmpy2.powmod(e_y, gmpy2.sub(N, 1), N_square)), N_square), r_1,
                             N_square),
                e_r1_add_r2), N_square)
    else:
        D = gmpy2.mod(
            gmpy2.mul(gmpy2.powmod(gmpy2.mod(gmpy2.mul(e_y, gmpy2.powmod(e_x, -1, N_square)), N_square), r_1, N_square),
                      e_r2),
            N_square)
    D1 = paillier_NewOpt.PDec(S_0.private_partial_key, D)

    '''
    send (D,D1) to S_1
    '''

    # step2,S_1
    D2 = paillier_NewOpt.PDec(S_1.private_partial_key, D)
    d = paillier_NewOpt.TDec(D1, D2, N)

    e_0, e_1 = tuple_S_1['e_0'], tuple_S_1['e_1']
    # refreshing ciphertext
    tuple_S_1['e_0'] = gmpy2.mod(gmpy2.mul(tuple_S_1['e_0'], tuple_S_1['e_0']), N_square)
    tuple_S_1['e_1'] = gmpy2.mod(gmpy2.mul(tuple_S_1['e_1'], tuple_S_1['e_0']), N_square)
    if d > N // 2:
        e_u0 = e_0
    else:
        e_u0 = e_1

    '''
    send e_u0 to S_0
    '''

    # # step3,S_0
    if pi == 0:
        e_u = e_u0
    else:
        e_1_for_S_0 = tuple_S_0['e_1']
        tuple_S_0['e_1'] = gmpy2.mod(gmpy2.mul(tuple_S_0['e_1'], tuple_S_0['e_0']), N_square)
        e_u = gmpy2.mod(gmpy2.mul(e_1_for_S_0, gmpy2.powmod(e_u0, -1, N_square)), N_square)

    return e_u


def sec_SSBA(e_x, tuple_S_0: dict, tuple_S_1: dict, S_0: Paillier_Third_party, S_1: Paillier_Third_party):
    '''
    the protocol of SSBA
    Return an encrypted e_s and an encrypted x'.
    After decryption, e_s is the sign bit (e.g., 0 or 1) of x, where 0 represents x is a non-negative number and 1 represents a negative number.
    After decryption, x' is the absolute value of x.
    :param e_x: Encrypted data x
    :param tuple_S_0: Tuple for pre-computation of S_0
    :param S_0:  Cloud Platform (S_0)
    :param S_1:Computation Service Provider (S_1)
    :return:
    '''
    public_key = S_0.public_key
    N = public_key['N']
    N_square = N ** 2

    # step1,S_0
    e_0, e_1 = tuple_S_0["e_0"], tuple_S_0["e_1"]
    # refreshing ciphertext
    tuple_S_0['e_0'] = gmpy2.mod(gmpy2.mul(tuple_S_0['e_0'], tuple_S_0['e_0']), N_square)
    tuple_S_0['e_1'] = gmpy2.mod(gmpy2.mul(tuple_S_0['e_1'], tuple_S_0['e_0']), N_square)

    # step2,S_1,S_0
    e_s = sec_cmp(e_x, e_0, tuple_S_0, tuple_S_1, S_0, S_1)

    # step3,S_0
    e_1sub_2s = gmpy2.mod(gmpy2.mul(e_1, gmpy2.powmod(e_s, -2, N_square)), N_square)

    # step4,S_0,S_1
    # x_another represents x'
    x_another = gmpy2.mod(sec_mul(e_1sub_2s, e_x, tuple_S_0, tuple_S_1, S_0, S_1), N_square)

    return e_s, x_another


def sec_div(e_x, e_y, tuple_S_0: dict, tuple_S_1: dict, l, S_0: Paillier_Third_party, S_1: Paillier_Third_party):
    '''
    the protocol of SDIV.
    The q and e returned in encrypted form, where q is the quotient of x divided by y and e is the remainder of x divided by y
    :param e_x: Encrypted data x, dividend
    :param e_y: Encrypted data y, divisor
    :param tuple_S_0:  Tuple for pre-computation of S_0
    :param l: l is the number of iterations and the bit length of plaintext
    :param S_0:  Cloud Platform (S_0)
    :param S_1:Computation Service Provider (S_1)
    :return:
    '''
    public_key = S_0.public_key
    N = public_key['N']
    N_square = N ** 2

    # step_1,S_0
    e_0, e_1 = tuple_S_0["e_0"], tuple_S_0["e_1"]
    # refreshing ciphertext
    tuple_S_0['e_0'] = gmpy2.mod(gmpy2.mul(tuple_S_0['e_0'], tuple_S_0['e_0']), N_square)
    tuple_S_0['e_1'] = gmpy2.mod(gmpy2.mul(tuple_S_0['e_1'], tuple_S_0['e_0']), N_square)

    e_q = e_0

    while l >= 0:
        # step_2,S_0
        e_c = gmpy2.powmod(e_y, 2 ** l, N_square)

        # step_3,S_0,S_1
        e_u = sec_cmp(e_x, e_c, tuple_S_0, tuple_S_1, S_0, S_1)

        # step_4,S_0
        # e_u_another is the encrypted u'
        e_u_another = gmpy2.mod(gmpy2.mul(e_1, gmpy2.powmod(e_u, -1, N_square)), N_square)
        e_q = gmpy2.mod(gmpy2.mul(e_q, gmpy2.powmod(e_u_another, 2 ** l, N_square)), N_square)

        # step_5, S_0,S_1
        e_m = sec_mul(e_u_another, e_c, tuple_S_0, tuple_S_1, S_0, S_1)

        # step_6, S_0
        e_x = gmpy2.mod(gmpy2.mul(e_x, gmpy2.powmod(e_m, -1, N_square)), N_square)

        l -= 1

    # step_7
    e_e = e_x
    return e_q, e_e
