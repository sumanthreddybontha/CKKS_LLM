#include "seal/seal.h"
#include <iostream>
#include <vector>
#include <cmath>

using namespace std;
using namespace seal;

int main() {
    // Step 1: Set encryption parameters for CKKS
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 60}));

    // Step 2: Create SEALContext
    SEALContext context(parms);

    // Step 3: Key generation
    KeyGenerator keygen(context);
    PublicKey public_key;
    SecretKey secret_key = keygen.secret_key();
    keygen.create_public_key(public_key);

    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);

    GaloisKeys gal_keys;
    keygen.create_galois_keys(gal_keys);

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    CKKSEncoder encoder(context);

    // Step 4: Encoding scale
    double scale = pow(2.0, 40);

    // Step 5: Prepare vectors
    vector<double> matrix1 = {1.0, 2.0};
    vector<double> matrix2 = {3.0, 4.0};

    Plaintext plain1, plain2;
    encoder.encode(matrix1, scale, plain1);
    encoder.encode(matrix2, scale, plain2);

    // Step 6: Encrypt vectors
    Ciphertext encrypted1, encrypted2;
    encryptor.encrypt(plain1, encrypted1);
    encryptor.encrypt(plain2, encrypted2);

    // Step 7: Multiply
    Ciphertext encrypted_result;
    evaluator.multiply(encrypted1, encrypted2, encrypted_result);
    evaluator.relinearize_inplace(encrypted_result, relin_keys);
    evaluator.rescale_to_next_inplace(encrypted_result);

    // Step 8: Decrypt result
    Plaintext plain_result;
    decryptor.decrypt(encrypted_result, plain_result);

    vector<double> result;
    encoder.decode(plain_result, result);

    cout << "Homomorphic result (approx): " << result[0] << endl;

    return 0;
}
