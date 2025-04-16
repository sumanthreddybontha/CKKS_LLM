#include <seal/seal.h>
#include <iostream>
#include <vector>
#include <cmath>

using namespace std;
using namespace seal;

int main() {
    // Step 1: Set CKKS encryption parameters
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(
        poly_modulus_degree, {60, 40, 40, 60}));

    SEALContext context(parms);
    //print_parameters(context);
    cout << endl;

    // Step 2: Key generation
    KeyGenerator keygen(context);
    
    PublicKey public_key;
    keygen.create_public_key(public_key);

    SecretKey secret_key = keygen.secret_key();

    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);

    GaloisKeys gal_keys;
    keygen.create_galois_keys(gal_keys);

    // Step 3: Setup tools
    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    CKKSEncoder encoder(context);

    double scale = pow(2.0, 40);

    // Step 4: Input and kernel
    vector<double> input = {10.0, 20.0, 30.0};      // Signal
    vector<double> kernel = {0.1, 0.2, 0.7};        // Smoothing kernel

    // Encode and encrypt the input
    Plaintext pt_input;
    encoder.encode(input, scale, pt_input);

    Ciphertext ct_input;
    encryptor.encrypt(pt_input, ct_input);

    // Encode kernel as plaintext scalars
    Plaintext k0, k1, k2;
    encoder.encode(kernel[0], scale, k0);
    encoder.encode(kernel[1], scale, k1);
    encoder.encode(kernel[2], scale, k2);

    // Rotate input
    Ciphertext rot_left, rot_right;
    evaluator.rotate_vector(ct_input, 1, gal_keys, rot_left);
    evaluator.rotate_vector(ct_input, -1, gal_keys, rot_right);

    // Multiply each shifted ciphertext with corresponding kernel value
    Ciphertext mul_left, mul_center, mul_right;

    evaluator.multiply_plain(rot_left, k0, mul_left);
    evaluator.rescale_to_next_inplace(mul_left);

    evaluator.multiply_plain(ct_input, k1, mul_center);
    evaluator.rescale_to_next_inplace(mul_center);

    evaluator.multiply_plain(rot_right, k2, mul_right);
    evaluator.rescale_to_next_inplace(mul_right);

    // Match scales and modulus for all ciphertexts
    parms_id_type last_parms_id = mul_center.parms_id();
    evaluator.mod_switch_to_inplace(mul_left, last_parms_id);
    evaluator.mod_switch_to_inplace(mul_right, last_parms_id);

    // Sum all parts
    Ciphertext result;
    evaluator.add(mul_left, mul_center, result);
    evaluator.add_inplace(result, mul_right);

    // Decrypt and decode
    Plaintext result_plain;
    decryptor.decrypt(result, result_plain);

    vector<double> output;
    encoder.decode(result_plain, output);

    // Print result
    cout << "Encrypted convolution result (approximate): ";
    for (double val : output)
        cout << val << " ";
    cout << endl;

    return 0;
}