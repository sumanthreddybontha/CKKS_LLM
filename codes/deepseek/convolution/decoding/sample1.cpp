#include <iostream>
#include <vector>
#include <seal/seal.h>

using namespace std;
using namespace seal;

vector<double> simple_convolution(const vector<double>& input, const vector<double>& kernel) {
    size_t input_size = input.size();
    size_t kernel_size = kernel.size();
    size_t output_size = input_size + kernel_size - 1;
    vector<double> output(output_size, 0.0);

    for (size_t i = 0; i < input_size; ++i) {
        for (size_t j = 0; j < kernel_size; ++j) {
            output[i + j] += input[i] * kernel[j];
        }
    }

    return output;
}

int main() {
    cout << "Setting up CKKS environment..." << endl;

    // 1. Parameter setup
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {40, 40, 40, 40, 40}));

    SEALContext context(parms);
    cout << "Parameters validation: " << context.parameter_error_message() << endl;

    // 2. Key generation
    KeyGenerator keygen(context);
    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys gal_keys;
    keygen.create_galois_keys(gal_keys);

    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    CKKSEncoder encoder(context);
    size_t slot_count = encoder.slot_count();
    cout << "Number of slots: " << slot_count << endl;

    // 3. Prepare input data
    vector<double> input1{1.0, 2.0, 3.0, 4.0};
    vector<double> input2{0.5, 0.25, 0.125, 0.0625};
    
    // Pad vectors to half of slot count
    input1.resize(slot_count / 2, 0.0);
    input2.resize(slot_count / 2, 0.0);

    cout << "Encoding and encrypting data..." << endl;
    Plaintext plain1, plain2;
    encoder.encode(input1, pow(2.0, 20), plain1);
    encoder.encode(input2, pow(2.0, 20), plain2);

    Ciphertext cipher1, cipher2;
    encryptor.encrypt(plain1, cipher1);
    encryptor.encrypt(plain2, cipher2);

    // 4. Perform convolution (multiplication in CKKS)
    cout << "Performing convolution..." << endl;
    Ciphertext encrypted_result;
    evaluator.multiply(cipher1, cipher2, encrypted_result);
    evaluator.relinearize_inplace(encrypted_result, relin_keys);
    evaluator.rescale_to_next_inplace(encrypted_result);

    // 5. Decrypt and decode
    Plaintext plain_result;
    decryptor.decrypt(encrypted_result, plain_result);

    vector<double> result;
    encoder.decode(plain_result, result);
    result.resize(7); // Expected convolution size for 4x4 inputs

    // 6. Compute expected result
    vector<double> expected = simple_convolution(
        vector<double>{1.0, 2.0, 3.0, 4.0},
        vector<double>{0.5, 0.25, 0.125, 0.0625}
    );

    // 7. Verification
    cout << "\nVerifying results..." << endl;
    cout << "Expected: ";
    for (auto val : expected) cout << val << " ";
    cout << "\nActual:   ";
    for (size_t i = 0; i < expected.size(); i++) cout << result[i] << " ";
    cout << endl;

    cout << "Done." << endl;
    return 0;
}