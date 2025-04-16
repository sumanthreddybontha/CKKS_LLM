#include "seal/seal.h"
#include <iostream>
#include <vector>
#include <cmath>

using namespace std;
using namespace seal;

int main() {
    // Step 1: Set CKKS parameters
    size_t poly_modulus_degree = 8192;
    EncryptionParameters parms(scheme_type::ckks);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 60}));

    // Step 2: Create context
    SEALContext context(parms);

    // Step 3: Key generation
    KeyGenerator keygen(context);
    PublicKey public_key;
    keygen.create_public_key(public_key);

    SecretKey secret_key = keygen.secret_key();

    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    CKKSEncoder encoder(context);

    double scale = pow(2.0, 40);

    // Step 4: Input matrices as flat vectors
    vector<double> mat1 = {1.0, 2.0, 3.0, 4.0};
    vector<double> mat2 = {5.0, 6.0, 7.0, 8.0};

    // Step 5: Encode
    Plaintext plain1, plain2;
    encoder.encode(mat1, scale, plain1);
    encoder.encode(mat2, scale, plain2);

    // Step 6: Encrypt
    Ciphertext encrypted1, encrypted2;
    encryptor.encrypt(plain1, encrypted1);
    encryptor.encrypt(plain2, encrypted2);

    // Step 7: Element-wise multiplication (Hadamard product)
    Ciphertext encrypted_result;
    evaluator.multiply(encrypted1, encrypted2, encrypted_result);
    evaluator.relinearize_inplace(encrypted_result, relin_keys);
    evaluator.rescale_to_next_inplace(encrypted_result);

    // Step 8: Decrypt and decode
    Plaintext plain_result;
    decryptor.decrypt(encrypted_result, plain_result);

    vector<double> result;
    encoder.decode(plain_result, result);

    // Step 9: Print result
    cout << "Decrypted result (Hadamard product):" << endl;
    for (size_t i = 0; i < mat1.size(); ++i) {
        cout << result[i] << " ";
        if ((i + 1) % 2 == 0) cout << endl;
    }

    return 0;
}
