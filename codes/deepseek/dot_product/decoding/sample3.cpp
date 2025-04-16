#include <iostream>
#include <vector>
#include <seal/seal.h>

using namespace std;
using namespace seal;

void print_parameters(const SEALContext &context) {
    auto &context_data = *context.key_context_data();
    cout << "Encryption parameters:" << endl;
    cout << "  scheme: CKKS" << endl;
    cout << "  poly_modulus_degree: " << context_data.parms().poly_modulus_degree() << endl;
    cout << "  coeff_modulus size: " << context_data.total_coeff_modulus_bit_count() << " bits" << endl;
    cout << "  scale: " << context_data.parms().coeff_modulus().back().bit_count() << " bits" << endl;
}

int main() {
    // Step 1: CKKS setup
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));
    SEALContext context(parms);
    print_parameters(context);

    // Step 2: Keys and helpers
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

    double scale = pow(2.0, 40);

    // Step 3: Input vectors
    vector<double> vec1 = { 1.0, 2.0, 3.0, 4.0 };
    vector<double> vec2 = { 5.0, 6.0, 7.0, 8.0 };

    // Step 4: Encode and encrypt
    Plaintext plain1, plain2;
    encoder.encode(vec1, scale, plain1);
    encoder.encode(vec2, scale, plain2);

    Ciphertext encrypted1, encrypted2;
    encryptor.encrypt(plain1, encrypted1);
    encryptor.encrypt(plain2, encrypted2);

    // Step 5: Element-wise multiplication
    Ciphertext multiplied;
    evaluator.multiply(encrypted1, encrypted2, multiplied);
    evaluator.relinearize_inplace(multiplied, relin_keys);
    evaluator.rescale_to_next_inplace(multiplied);

    // Step 6: Sum all elements to get the dot product
    // First align scale and modulus
    auto last_parms_id = multiplied.parms_id();
    Ciphertext sum = multiplied;

    for (size_t i = 1; i < vec1.size(); i++) {
        Ciphertext rotated;
        evaluator.rotate_vector(sum, i, gal_keys, rotated);
        evaluator.add_inplace(sum, rotated);
    }

    // Step 7: Decrypt and decode
    Plaintext plain_result;
    decryptor.decrypt(sum, plain_result);
    vector<double> result;
    encoder.decode(plain_result, result);

    cout << "Dot product result: " << result[0] << endl;

    return 0;
}