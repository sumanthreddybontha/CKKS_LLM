#include "seal/seal.h"
#include <iostream>
#include <vector>

using namespace std;
using namespace seal;

int main() {
    // Step 1: Set encryption parameters for CKKS
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));

    double scale = pow(2.0, 40);
    SEALContext context(parms);

    // Step 2: Generate keys
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();

    PublicKey public_key;
    keygen.create_public_key(public_key);

    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    CKKSEncoder encoder(context);

    // Step 3: Input matrices as vectors (flattened)
    vector<double> matA = { 1.0, 2.0, 3.0, 4.0 }; // 2x2
    vector<double> matB = { 5.0, 6.0, 7.0, 8.0 }; // 2x2

    Plaintext plainA, plainB;
    encoder.encode(matA, scale, plainA);
    encoder.encode(matB, scale, plainB);

    Ciphertext encryptedA, encryptedB;
    encryptor.encrypt(plainA, encryptedA);
    encryptor.encrypt(plainB, encryptedB);

    // Step 4: Multiply ciphertexts element-wise (RAG-style op)
    Ciphertext encrypted_result;
    evaluator.multiply(encryptedA, encryptedB, encrypted_result);
    evaluator.relinearize_inplace(encrypted_result, relin_keys);
    evaluator.rescale_to_next_inplace(encrypted_result);

    // Step 5: Decrypt and decode
    Plaintext plain_result;
    decryptor.decrypt(encrypted_result, plain_result);
    vector<double> result;
    encoder.decode(plain_result, result);

    // Output
    cout << "Result (element-wise multiply):" << endl;
    for (double val : result) {
        cout << val << " ";
    }
    cout << endl;

    return 0;
}
