#include <iostream>
#include <vector>
#include "seal/seal.h"

using namespace std;
using namespace seal;

int main() {
    // 1. Minimal parameter setup for 64-bit security
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {40, 30, 30, 40}));

    SEALContext context(parms);
    KeyGenerator keygen(context);
    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    CKKSEncoder encoder(context);
    double scale = pow(2.0, 30);

    // 2. Batch encoding for two 4-element vectors
    vector<double> vec1 = {1.0, 2.0, 3.0, 4.0};
    vector<double> vec2 = {5.0, 6.0, 7.0, 8.0};
    
    Plaintext plain1, plain2;
    encoder.encode(vec1, scale, plain1);
    encoder.encode(vec2, scale, plain2);

    Ciphertext cipher1, cipher2;
    encryptor.encrypt(plain1, cipher1);
    encryptor.encrypt(plain2, cipher2);

    // Multiplication
    evaluator.multiply_inplace(cipher1, cipher2);
    evaluator.relinearize_inplace(cipher1, relin_keys);
    evaluator.rescale_to_next_inplace(cipher1);

    // 3. Selective extraction of only the first multiplication result
    Plaintext plain_result;
    decryptor.decrypt(cipher1, plain_result);
    
    vector<double> result;
    encoder.decode(plain_result, result);
    
    // Only output the first result (1.0 * 5.0 = 5.0)
    cout << "First element result: " << result[0] << endl;

    return 0;
}