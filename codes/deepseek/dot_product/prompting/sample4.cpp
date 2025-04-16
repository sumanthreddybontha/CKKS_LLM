#include <iostream>
#include <vector>
#include <complex>
#include <seal/seal.h>

using namespace std;
using namespace seal;

int main() {
    cout << "CKKS Dot Product: Complex Numbers Implementation" << endl;

    // Parameters
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));

    // Context
    auto context = SEALContext::Create(parms);

    // Keys
    KeyGenerator keygen(context);
    auto public_key = keygen.public_key();
    auto secret_key = keygen.secret_key();
    auto relin_keys = keygen.relin_keys();
    GaloisKeys gal_keys = keygen.galois_keys();

    // Utilities
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    CKKSEncoder encoder(context);
    size_t slot_count = encoder.slot_count();

    // Complex vectors
    vector<complex<double>> complex_vec1, complex_vec2;
    for (size_t i = 0; i < 4; i++) {
        complex_vec1.push_back({1.0 * (i+1), 0.5 * (i+1)});
        complex_vec2.push_back({2.0 * (i+1), 0.25 * (i+1)});
    }
    complex_vec1.resize(slot_count, {0, 0});
    complex_vec2.resize(slot_count, {0, 0});

    // Encode and encrypt
    Plaintext plain_vec1, plain_vec2;
    encoder.encode(complex_vec1, pow(2.0, 40), plain_vec1);
    encoder.encode(complex_vec2, pow(2.0, 40), plain_vec2);

    Ciphertext encrypted_vec1, encrypted_vec2;
    encryptor.encrypt(plain_vec1, encrypted_vec1);
    encryptor.encrypt(plain_vec2, encrypted_vec2);

    // Complex multiplication (dot product)
    // For complex numbers, dot product is sum of element-wise multiplications
    Ciphertext encrypted_product;
    evaluator.multiply(encrypted_vec1, encrypted_vec2, encrypted_product);
    evaluator.relinearize_inplace(encrypted_product, relin_keys);
    evaluator.rescale_to_next_inplace(encrypted_product);

    // Sum all elements
    Ciphertext encrypted_sum = encrypted_product;
    for (size_t i = 1; i < slot_count; i *= 2) {
        Ciphertext rotated;
        evaluator.rotate_vector(encrypted_sum, i, gal_keys, rotated);
        evaluator.add_inplace(encrypted_sum, rotated);
    }

    // Decrypt and decode
    Plaintext plain_sum;
    decryptor.decrypt(encrypted_sum, plain_sum);
    vector<complex<double>> sum;
    encoder.decode(plain_sum, sum);

    // Calculate expected result
    complex<double> expected(0, 0);
    for (size_t i = 0; i < 4; i++) {
        expected += complex_vec1[i] * conj(complex_vec2[i]);
    }

    cout << "Complex dot product result: " << sum[0] << endl;
    cout << "Expected result: " << expected << endl;

    return 0;
}