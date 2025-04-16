// Flattened Vector Encoding Approach
#include "seal/seal.h"
#include <iostream>
#include <vector>
#include <cmath>
#include <sstream>

using namespace std;
using namespace seal;

int main() {
    // CKKS parameter setup
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 60}));
    double scale = pow(2.0, 40);

    SEALContext context(parms);
    KeyGenerator keygen(context);

    // Serialize and load public key
    Serializable<PublicKey> public_key_serial = keygen.create_public_key();
    PublicKey public_key;
    std::stringstream public_key_stream;
    public_key_serial.save(public_key_stream);
    public_key.load(context, public_key_stream);

    SecretKey secret_key = keygen.secret_key();
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    CKKSEncoder encoder(context);

    // Input matrices
    vector<double> flat_matrix_a = {1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0};
    vector<double> flat_matrix_b = {9.0, 8.0, 7.0, 6.0, 5.0, 4.0, 3.0, 2.0, 1.0};

    Plaintext plain_matrix_a, plain_matrix_b;
    encoder.encode(flat_matrix_a, scale, plain_matrix_a);
    encoder.encode(flat_matrix_b, scale, plain_matrix_b);

    Ciphertext encrypted_matrix_a;
    encryptor.encrypt(plain_matrix_a, encrypted_matrix_a);

    // Perform element-wise multiplication
    Ciphertext result = encrypted_matrix_a;
    evaluator.multiply_plain_inplace(result, plain_matrix_b);
    evaluator.rescale_to_next_inplace(result);

    // Decrypt and decode
    Plaintext decrypted_result;
    decryptor.decrypt(result, decrypted_result);
    vector<double> decoded_result;
    encoder.decode(decrypted_result, decoded_result);

    // Output
    cout << "Decrypted matrix product (flat): ";
    for (const auto &val : decoded_result) {
        cout << val << " ";
    }
    cout << endl;

    return 0;
}
