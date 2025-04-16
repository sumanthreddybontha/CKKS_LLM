#include "seal/seal.h"
#include <iostream>
#include <vector>

using namespace std;
using namespace seal;

int main() {
    // Step 1: Set encryption parameters
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 60}));

    // Step 2: Set up context
    auto context = SEALContext::Create(parms);

    // Step 3: Generate keys
    KeyGenerator keygen(context);
    auto public_key = keygen.public_key();
    auto secret_key = keygen.secret_key();
    auto relin_keys = keygen.relin_keys();
    auto gal_keys = keygen.galois_keys();

    // Step 4: Create encryptor, decryptor, evaluator, encoder
    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    CKKSEncoder encoder(context);

    // Step 5: Encode input matrices
    size_t slot_count = encoder.slot_count();
    double scale = pow(2.0, 40);
    vector<double> matrix1 = {1.0, 2.0, 3.0, 4.0};
    vector<double> matrix2 = {5.0, 6.0, 7.0, 8.0};

    Plaintext plain1, plain2;
    encoder.encode(matrix1, scale, plain1);
    encoder.encode(matrix2, scale, plain2);

    // Step 6: Encrypt the encoded matrices
    Ciphertext encrypted1, encrypted2;
    encryptor.encrypt(plain1, encrypted1);
    encryptor.encrypt(plain2, encrypted2);

    // Step 7: Multiply matrices element-wise (SIMD)
    Ciphertext encrypted_result;
    evaluator.multiply(encrypted1, encrypted2, encrypted_result);
    evaluator.relinearize_inplace(encrypted_result, relin_keys);
    evaluator.rescale_to_next_inplace(encrypted_result);

    // Step 8: Decrypt and decode result
    Plaintext plain_result;
    decryptor.decrypt(encrypted_result, plain_result);
    vector<double> result;
    encoder.decode(plain_result, result);

    // Step 9: Print result
    cout << "Result: ";
    for (double val : result) {
        cout << val << " ";
    }
    cout << endl;

    return 0;
}
