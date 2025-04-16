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
    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    CKKSEncoder encoder(context);

    double scale = pow(2.0, 40);

    // Step 3: Vector and scalar
    vector<double> input_vector = { 1.5, 2.5, 3.5, 4.5 };
    double scalar = 3.14;

    // Step 4: Encode and encrypt vector
    Plaintext plain_vector;
    encoder.encode(input_vector, scale, plain_vector);
    Ciphertext encrypted_vector;
    encryptor.encrypt(plain_vector, encrypted_vector);

    // Step 5: Encode scalar as a plaintext vector (broadcasted)
    vector<double> scalar_vector(input_vector.size(), scalar);
    Plaintext plain_scalar;
    encoder.encode(scalar_vector, scale, plain_scalar);
    evaluator.mod_switch_to_inplace(plain_scalar, encrypted_vector.parms_id());

    // Step 6: Multiply encrypted vector with plaintext scalar
    Ciphertext encrypted_result;
    evaluator.multiply_plain(encrypted_vector, plain_scalar, encrypted_result);
    evaluator.rescale_to_next_inplace(encrypted_result);

    // Step 7: Decrypt and decode result
    Plaintext plain_result;
    decryptor.decrypt(encrypted_result, plain_result);
    vector<double> result;
    encoder.decode(plain_result, result);

    cout << "Result of vector * " << scalar << ": ";
    for (double val : result) {
        cout << val << " ";
    }
    cout << endl;

    return 0;
}