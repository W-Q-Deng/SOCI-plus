import random

import libnum

import pre_compute
import paillier_NewOpt
import SOCI_plus_protocol
from paillier_third_party import Paillier_Third_party


def offline_phase(public_key: dict, key_len=448):
    '''
    In the offline phase, construct a pre-computation table and generate two tuples
    :param public_key:
    :param key_len: the bit-length of private key
    :return: tuple_S_0,tuple_S_1
    '''
    # construct a pre-computation table
    table = pre_compute.construct_table(public_key['h_N'], public_key['N'] ** 2, l=key_len)
    public_key['table'] = table
    # construct two tuples for S_0 and S_1, respectively
    tuple_S_0 = {}
    tuple_S_0['r_1'] = libnum.randint_bits(128)
    tuple_S_0['r_2'] = libnum.randint_bits(128)
    tuple_S_0['e_r_1'] = paillier_NewOpt.Enc_NewOpt(public_key, tuple_S_0['r_1'])
    tuple_S_0['e_r_2'] = paillier_NewOpt.Enc_NewOpt(public_key, tuple_S_0['r_2'])
    tuple_S_0['e_negative_r1_r2'] = paillier_NewOpt.Enc_NewOpt(public_key, -tuple_S_0['r_1'] * tuple_S_0['r_2'])
    r_3 = random.randint(1, 2 ** 128)
    N = public_key['N']
    mid = N // 2
    while True:
        r = random.randint(1, 2 ** 128)
        if r < r_3:
            break
    r_4 = mid - r
    tuple_S_0['r_3'] = r_3
    tuple_S_0['r_4'] = r_4
    tuple_S_0['e_r3_add_r4'] = paillier_NewOpt.Enc_NewOpt(public_key, tuple_S_0['r_3'] + tuple_S_0['r_4'])
    tuple_S_0['e_r_4'] = paillier_NewOpt.Enc_NewOpt(public_key, tuple_S_0['r_4'])
    tuple_S_0['e_0'] = paillier_NewOpt.Enc_NewOpt(public_key, 0)
    tuple_S_0['e_1'] = paillier_NewOpt.Enc_NewOpt(public_key, 1)
    tuple_S_1 = {}
    tuple_S_1['e_0'] = paillier_NewOpt.Enc_NewOpt(public_key, 0)
    tuple_S_1['e_1'] = paillier_NewOpt.Enc_NewOpt(public_key, 1)
    return tuple_S_0, tuple_S_1


if __name__ == "__main__":
    # key generation
    private_key, public_key, private_key_1, private_key_2 = paillier_NewOpt.KGen_NewOpt(k=112)
    S_0 = Paillier_Third_party(public_key, private_key_1)
    S_1 = Paillier_Third_party(public_key, private_key_2)

    '''
        offline phase
        generate two tuples and a pre-computation table
    '''
    tuple_S_0, tuple_S_1 = offline_phase(public_key)

    '''
        online phase
    '''
    print('correctness testing\n')
    plaintext1 = [-i for i in range(1, 21, 1)]
    plaintext1.append(99)
    plaintext1.append(100)
    plaintext1.append(101)
    plaintext2 = [i for i in range(20, 0, -1)]
    plaintext2.append(101)
    plaintext2.append(100)
    plaintext2.append(99)
    print(f"plaintext list 1:{plaintext1}")
    print(f"plaintext list 2:{plaintext2}")

    ciphertext_list1 = []
    ciphertext_list2 = []
    result_smul = []
    result_scmp = []
    result_ssba = []
    result_div = []
    for i in range(len(plaintext1)):
        ciphertext_list1.append(paillier_NewOpt.Enc_NewOpt(public_key, plaintext1[i]))
        ciphertext_list2.append(paillier_NewOpt.Enc_NewOpt(public_key, plaintext2[i]))
        result_smul.append(plaintext1[i] * plaintext2[i])
        result_scmp.append(0 if plaintext1[i] >= plaintext2[i] else 1)
        result_ssba.append([0 if plaintext1[i] >= 0 else 1, abs(plaintext1[i])])

    print("\nSMUL")
    print("operation result in plaintext：")
    print(result_smul)
    result_dec_smul = []
    for i in range(len(plaintext1)):
        e_xy = SOCI_plus_protocol.sec_mul(ciphertext_list1[i], ciphertext_list2[i], tuple_S_0, tuple_S_1, S_0, S_1)
        result_dec_smul.append(paillier_NewOpt.Dec_NewOpt(private_key, e_xy))
    print("operation result in ciphertext")
    print(result_dec_smul)
    for i in range(len(plaintext1)):
        result_dec_smul[i] = int(result_dec_smul[i])
        if result_dec_smul[i] != result_smul[i]:
            print("wrong")
            break
    print("all correct!")

    print("\nSCMP")
    print("operation result in plaintext：")
    print(result_scmp)
    result_dec_scmp = []
    for i in range(len(plaintext1)):
        e_u = SOCI_plus_protocol.sec_cmp(ciphertext_list1[i], ciphertext_list2[i], tuple_S_0, tuple_S_1, S_0, S_1)
        result_dec_scmp.append(paillier_NewOpt.Dec_NewOpt(private_key, e_u))
    print("operation result in ciphertext")
    print(result_dec_scmp)
    for i in range(len(plaintext1)):
        result_dec_scmp[i] = int(result_dec_scmp[i])
        if result_dec_scmp[i] != result_scmp[i]:
            print("wrong")
            break
    print("all correct!")

    print("\nSSBA")
    print("operation result in plaintext：")
    print(result_ssba)
    result_dec_ssba = []
    for i in range(len(plaintext1)):
        e_s, another_x = SOCI_plus_protocol.sec_SSBA(ciphertext_list1[i], tuple_S_0, tuple_S_1, S_0, S_1)
        result_dec_ssba.append(
            [paillier_NewOpt.Dec_NewOpt(private_key, e_s), paillier_NewOpt.Dec_NewOpt(private_key, another_x)])
    print("operation result in ciphertext")
    print(result_dec_ssba)
    for i in range(len(plaintext1)):
        result_dec_ssba[i][0] = int(result_dec_ssba[i][0])
        result_dec_ssba[i][1] = int(result_dec_ssba[i][1])
        if result_dec_ssba[i][1] != result_ssba[i][1] or result_dec_ssba[i][0] != result_ssba[i][0]:
            print("wrong")
            break
    print("all correct!")

    print("\nSDIV (divisor greater than 0)")
    plaintext_div_1 = [i for i in range(20)]
    plaintext_div_1.append(99)
    plaintext_div_1.append(100)
    plaintext_div_1.append(101)
    plaintext_div_2 = [i for i in range(20, 0, -1)]
    plaintext_div_2.append(101)
    plaintext_div_2.append(100)
    plaintext_div_2.append(99)
    print(f"plaintext list 1 for dividend:{plaintext_div_1}")
    print(f"plaintext list 2 for divisor:{plaintext_div_2}")
    ciphertext_list1_div = []
    ciphertext_list2_div = []
    for i in range(len(plaintext_div_1)):
        ciphertext_list1_div.append(paillier_NewOpt.Enc_NewOpt(public_key, plaintext_div_1[i]))
        ciphertext_list2_div.append(paillier_NewOpt.Enc_NewOpt(public_key, plaintext_div_2[i]))
        result_div.append([plaintext_div_1[i] // plaintext_div_2[i], plaintext_div_1[i] % plaintext_div_2[i]])
    print("operation result in plaintext：")
    print(result_div)
    result_dec_sdiv = []
    for i in range(len(plaintext1)):
        e_q, e_e = SOCI_plus_protocol.sec_div(ciphertext_list1_div[i], ciphertext_list2_div[i], tuple_S_0, tuple_S_1,
                                              32, S_0, S_1)
        result_dec_sdiv.append(
            [paillier_NewOpt.Dec_NewOpt(private_key, e_q), paillier_NewOpt.Dec_NewOpt(private_key, e_e)])
    print("operation result in ciphertext")
    print(result_dec_sdiv)
    for i in range(len(plaintext1)):
        result_dec_sdiv[i][0] = int(result_dec_sdiv[i][0])
        result_dec_sdiv[i][1] = int(result_dec_sdiv[i][1])
        if result_dec_sdiv[i][0] != result_div[i][0] or result_dec_sdiv[i][1] != result_div[i][1]:
            print("wrong")
            break
    print("all correct!")
