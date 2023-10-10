# The source codes of SOCI<sup>+</sup>
## Title of Paper
SOCI<sup>+</sup>: An Enhanced Toolkit for Secure OutsourcedComputation on Integers.
## Introduction
Secure outsourced computation is critical for cloud computing to safeguard data confidentiality and ensure data usability. Recently, secure outsourced computation schemes following a twin-server architecture based on partially homomorphic cryptosystems have received increasing attention. The Secure Outsourced Computation on Integers (SOCI) toolkit is the state-of-the-art among these schemes which can perform secure computation on integers without requiring the costly bootstrapping operation as in fully homomorphic encryption; however,
SOCI suffers from relatively large computation and communication overhead. In this paper, we propose SOCI<sup>+</sup> which significantly improves the performance of SOCI. Specifically, SOCI<sup>+</sup> employs a novel (2, 2)-threshold Paillier cryptosystem with fast encryption and decryption as its cryptographic primitive, and supports a suite of efficient secure arithmetic computation on integers protocols, including a secure multiplication protocol (SMUL), a secure comparison protocol (SCMP), a secure sign bit-acquisition protocol (SSBA), and a secure division protocol (SDIV), all based on the (2, 2)-threshold Paillier cryptosystem with fast encryption and decryption. In addition, SOCI<sup>+</sup> incorporates an offline and online computation mechanism to further optimize its performance. We perform rigorous theoretical analysis to prove the correctness and security of SOCI<sup>+</sup>. Compared with SOCI, our experimental evaluation shows that SOCI<sup>+</sup> is up to 5.4 times more efficient in computation and 40% less in communication overhead.
## Link of Paper
https://arxiv.org/pdf/2309.15406.pdf


