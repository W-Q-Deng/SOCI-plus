class Paillier_Third_party:
    '''
    The third parties involved in SOCI^+ computing protocols, including S_0 and S_1
    '''

    def __init__(self, public_key, private_partial_key):
        '''
        :param public_key:
        :param private_partial_key:the partial private key of S_0 or S_1
        '''
        self.public_key = public_key
        self.private_partial_key = private_partial_key
        self.sigma = public_key['sigma']
