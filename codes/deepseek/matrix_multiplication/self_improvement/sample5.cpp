#include "seal/seal.h"
#include <iostream>
#include <vector>
#include <cmath>

using namespace std;
using namespace seal;

// Helper function to print encryption parameters
void print_parameters(const SEALContext &context)
{
    auto &context_data = *context.key_context_data();
    cout << "Encryption parameters:" << endl;
    cout << "  Scheme: CKKS" << endl;
    cout << "  Poly modulus degree: " << context_data.parms().poly_modulus_degree() << endl;

    cout << "  Coeff modulus size: ";
    auto coeff_modulus = context_data.parms().coeff_modulus();
    size_t total_bits = 0;
    for (const auto &mod : coeff_modulus)
    {
        total_bits += mod.bit_count();
        cout << mod.bit_count() << " ";
    }
    cout << "(" << total_bits << " bits)" << endl;
    cout << endl;
}

int main() {
    // Step 1: Set up encryption parameters
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 60}));

    SEALContext context(parms);
    print_parameters(context);

    // Step 2: Key generation
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

    // Step 3: Create and encode the vector (full slot packing)
    size_t slot_count = encoder.slot_count();
    vector<double> input(slot_count);
    for (size_t i = 0; i < slot_count; ++i) {
        input[i] = i + 1.0;  // Example values: [1.0, 2.0, ..., slot_count]
    }

    Plaintext plain;
    encoder.encode(input, scale, plain);

    // Step 4: Encrypt the data
    Ciphertext encrypted;
    encryptor.encrypt(plain, encrypted);

    // Step 5: Apply transformation (e.g., multiply by constant factor)
    double factor = 2.5;
    Plaintext plain_factor;
    encoder.encode(factor, scale, plain_factor);
    evaluator.multiply_plain_inplace(encrypted, plain_factor);
    evaluator.rescale_to_next_inplace(encrypted);

    // Step 6: Decrypt and decode
    Plaintext decrypted;
    decryptor.decrypt(encrypted, decrypted);
    vector<double> result;
    encoder.decode(decrypted, result);

    // Step 7: Selectively extract output (e.g., first 10 values)
    cout << "First 10 transformed values:" << endl;
    for (size_t i = 0; i < 10; ++i) {
        cout << "Result[" << i << "] = " << result[i] << endl;
    }

    return 0;
}
