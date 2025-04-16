#include <iostream>
#include <vector>
#include <seal/seal.h>

using namespace std;
using namespace seal;

int main() {
    cout << "CKKS Dot Product: Using Rotations Implementation" << endl;

    // Parameter setup
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));

    // Context creation
    auto context = SEALContext::Create(parms);

    // Key generation
    KeyGenerator keygen(context);
    auto public_key = keygen.public_key();
    auto secret_key = keygen.secret_key();
    auto relin_keys = keygen.relin_keys();
    GaloisKeys gal_keys = keygen.galois_keys();

    // Setup utilities
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    CKKSEncoder encoder(context);
    size_t slot_count = encoder.slot_count();

    // Input vectors
    vector<double> vec1{ 1.1, 2.2, 3.3, 4.4 };
    vector<double> vec2{ 2.0, 3.0, 4.0, 5.0 };
    vec1.resize(slot_count, 0.0);
    vec2.resize(slot_count, 0.0);

    // Encode and encrypt
    Plaintext plain_vec1, plain_vec2;
    encoder.encode(vec1, pow(2.0, 40), plain_vec1);
    encoder.encode(vec2, pow(2.0, 40), plain_vec2);

    Ciphertext encrypted_vec1, encrypted_vec2;
    encryptor.encrypt(plain_vec1, encrypted_vec1);
    encryptor.encrypt(plain_vec2, encrypted_vec2);

    // Multiply element-wise
    Ciphertext encrypted_product;
    evaluator.multiply(encrypted_vec1, encrypted_vec2, encrypted_product);
    evaluator.relinearize_inplace(encrypted_product, relin_keys);
    evaluator.rescale_to_next_inplace(encrypted_product);

    // Sum all elements using rotations
    Ciphertext encrypted_sum = encrypted_product;
    for (size_t i = 1; i < slot_count; i *= 2) {
        Ciphertext rotated;
        evaluator.rotate_vector(encrypted_sum, i, gal_keys, rotated);
        evaluator.add_inplace(encrypted_sum, rotated);
    }

    // Decrypt and decode
    Plaintext plain_sum;
    decryptor.decrypt(encrypted_sum, plain_sum);
    vector<double> sum;
    encoder.decode(plain_sum, sum);

    cout << "Dot product result: " << sum[0] << endl;
    cout << "Expected result: " << 1.1*2.0 + 2.2*3.0 + 3.3*4.0 + 4.4*5.0 << endl;

    return 0;
}