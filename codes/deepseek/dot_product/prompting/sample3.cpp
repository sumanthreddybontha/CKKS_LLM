#include <iostream>
#include <vector>
#include <seal/seal.h>

using namespace std;
using namespace seal;

int main() {
    // Initialize CKKS
    EncryptionParameters parms(scheme_type::ckks);
    parms.set_poly_modulus_degree(8192);
    parms.set_coeff_modulus(CoeffModulus::Create(8192, {50, 30, 30, 50}));

    SEALContext context(parms);
    KeyGenerator keygen(context);
    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys galois_keys;
    keygen.create_galois_keys(galois_keys);

    // Prepare crypto objects
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    CKKSEncoder encoder(context);
    size_t slot_count = encoder.slot_count();

    // Get user input
    size_t vec_size;
    cout << "Enter vector size (max " << slot_count << "): ";
    cin >> vec_size;
    vec_size = min(vec_size, slot_count);

    vector<double> vec1(vec_size), vec2(vec_size);
    cout << "Enter first vector elements: ";
    for (auto &x : vec1) cin >> x;
    cout << "Enter second vector elements: ";
    for (auto &x : vec2) cin >> x;

    // Pad vectors
    vec1.resize(slot_count, 0.0);
    vec2.resize(slot_count, 0.0);

    // Encrypt vectors
    double scale = pow(2.0, 40);
    Plaintext plain1, plain2;
    encoder.encode(vec1, scale, plain1);
    encoder.encode(vec2, scale, plain2);
    Ciphertext encrypted1, encrypted2;
    encryptor.encrypt(plain1, encrypted1);
    encryptor.encrypt(plain2, encrypted2);

    // Compute dot product
    evaluator.multiply_inplace(encrypted1, encrypted2);
    evaluator.relinearize_inplace(encrypted1, relin_keys);
    evaluator.rescale_to_next_inplace(encrypted1);

    // Sum elements
    Ciphertext result = encrypted1;
    for (size_t i = 1; i < slot_count; i *= 2) {
        Ciphertext rotated;
        evaluator.rotate_vector(result, i, galois_keys, rotated);
        evaluator.add_inplace(result, rotated);
    }

    // Get result
    Plaintext plain_result;
    decryptor.decrypt(result, plain_result);
    vector<double> decoded;
    encoder.decode(plain_result, decoded);

    cout << "Computed dot product: " << decoded[0] << endl;
    return 0;
}