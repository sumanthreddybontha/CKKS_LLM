#include <iostream>
#include <vector>
#include <seal/seal.h>

using namespace std;
using namespace seal;

int main() {
    cout << "CKKS Dot Product: Optimized with Scale Management" << endl;

    // Parameters with larger poly modulus for more operations
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 16384;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 40, 60 }));

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

    // Input vectors - larger vectors
    vector<double> vec1(slot_count), vec2(slot_count);
    for (size_t i = 0; i < slot_count; i++) {
        vec1[i] = (i % 10) * 0.1;
        vec2[i] = (i % 5) * 0.2;
    }

    // Encode with appropriate scale
    double scale = pow(2.0, 50);
    Plaintext plain_vec1, plain_vec2;
    encoder.encode(vec1, scale, plain_vec1);
    encoder.encode(vec2, scale, plain_vec2);

    // Encrypt
    Ciphertext encrypted_vec1, encrypted_vec2;
    encryptor.encrypt(plain_vec1, encrypted_vec1);
    encryptor.encrypt(plain_vec2, encrypted_vec2);

    // Multiply
    evaluator.multiply_inplace(encrypted_vec1, encrypted_vec2);
    evaluator.relinearize_inplace(encrypted_vec1, relin_keys);
    evaluator.rescale_to_next_inplace(encrypted_vec1);

    // Adjust scale for summation
    encrypted_vec1.scale() = scale;

    // Sum all elements using optimal rotation strategy
    Ciphertext sum_ctxt = encrypted_vec1;
    size_t curr_size = slot_count;
    while (curr_size > 1) {
        curr_size /= 2;
        Ciphertext rotated;
        evaluator.rotate_vector(sum_ctxt, curr_size, gal_keys, rotated);
        evaluator.add_inplace(sum_ctxt, rotated);
    }

    // Decrypt and decode
    Plaintext plain_result;
    decryptor.decrypt(sum_ctxt, plain_result);
    vector<double> result;
    encoder.decode(plain_result, result);

    // Calculate expected result
    double expected = 0.0;
    for (size_t i = 0; i < slot_count; i++) {
        expected += vec1[i] * vec2[i];
    }

    cout << "Computed dot product: " << result[0] << endl;
    cout << "Expected dot product: " << expected << endl;
    cout << "Absolute error: " << abs(result[0] - expected) << endl;

    return 0;
}