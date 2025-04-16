#include "seal/seal.h"
#include <iostream>
#include <vector>

using namespace std;
using namespace seal;

int main() {
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 60}));
    SEALContext context(parms);

    KeyGenerator keygen(context);
    PublicKey public_key;
    SecretKey secret_key = keygen.secret_key();
    RelinKeys relin_keys;
    keygen.create_public_key(public_key);
    keygen.create_relin_keys(relin_keys);

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    CKKSEncoder encoder(context);
    double scale = pow(2.0, 30); // Lower scale than before

    vector<double> A = {2.0, 3.0}; // a00, a01
    vector<double> B = {4.0, 5.0}; // b00, b10

    Plaintext pA, pB;
    encoder.encode(A, scale, pA);
    encoder.encode(B, scale, pB);

    Ciphertext cA, cB;
    encryptor.encrypt(pA, cA);
    encryptor.encrypt(pB, cB);

    // Multiply elementwise for dot product (a00*b00 + a01*b10)
    Ciphertext prod;
    evaluator.multiply(cA, cB, prod);
    evaluator.relinearize_inplace(prod, relin_keys);
    evaluator.rescale_to_next_inplace(prod);

    Plaintext result;
    vector<double> vec;
    decryptor.decrypt(prod, result);
    encoder.decode(result, vec);

    cout << "Homomorphic Dot Product with Relinearization:" << endl;
    for (auto val : vec) {
        cout << val << " ";
    }
    cout << endl;

    return 0;
}