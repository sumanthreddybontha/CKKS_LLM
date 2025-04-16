#include <iostream>
#include <vector>
#include "seal/seal.h"

using namespace std;
using namespace seal;

vector<double> conv1d_basic(const vector<double>& input, const vector<double>& kernel) {
    // Set up encryption parameters
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 60}));

    SEALContext context(parms);
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
    double scale = pow(2.0, 40);

    // Encode and encrypt input vector
    Plaintext plain_input;
    encoder.encode(input, scale, plain_input);
    Ciphertext encrypted_input;
    encryptor.encrypt(plain_input, encrypted_input);

    // Encode and encrypt kernel
    Plaintext plain_kernel;
    encoder.encode(kernel, scale, plain_kernel);
    Ciphertext encrypted_kernel;
    encryptor.encrypt(plain_kernel, encrypted_kernel);

    // Compute convolution via multiplication in frequency domain
    evaluator.multiply_inplace(encrypted_input, encrypted_kernel);
    evaluator.relinearize_inplace(encrypted_input, relin_keys);
    evaluator.rescale_to_next_inplace(encrypted_input);

    // Decrypt and decode result
    Plaintext plain_result;
    decryptor.decrypt(encrypted_input, plain_result);
    vector<double> result;
    encoder.decode(plain_result, result);

    // Return only the valid part of the convolution
    size_t output_size = input.size() + kernel.size() - 1;
    return vector<double>(result.begin(), result.begin() + output_size);
}

int main() {
    // Example usage
    vector<double> input = {1.0, 2.0};
    vector<double> kernel = {0.5, 0.5};
    
    auto result = conv1d_basic(input, kernel);
    
    // Print final result
    cout << "Convolution result: ";
    for (auto val : result) {
        cout << val << " ";
    }
    cout << endl;
    
    return 0;
}