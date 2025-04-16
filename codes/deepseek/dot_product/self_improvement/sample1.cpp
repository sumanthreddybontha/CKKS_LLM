#include <iostream>
#include <vector>
#include <cmath>
#include <seal/seal.h>

using namespace std;
using namespace seal;

void print_parameters(const SEALContext &context) {
    auto &context_data = *context.key_context_data();
    cout << "\n/ Encryption parameters:" << endl;
    cout << "| scheme: CKKS" << endl;
    cout << "| poly_modulus_degree: " << context_data.parms().poly_modulus_degree() << endl;
    cout << "| coeff_modulus size: ";
    for (const auto &mod : context_data.parms().coeff_modulus()) {
        cout << mod.bit_count() << " ";
    }
    cout << "\n\\ scale: 2^" << log2(context_data.parms().coeff_modulus().back().value()) << endl;
}

void print_noise(const Decryptor &decryptor, const Ciphertext &ciphertext, const string &tag) {
    cout << "Noise budget in " << tag << ": "
         << decryptor.invariant_noise_budget(ciphertext) << " bits" << endl;
}

vector<double> simple_convolution(const vector<double> &input, const vector<double> &kernel) {
    size_t input_size = input.size();
    size_t kernel_size = kernel.size();
    vector<double> result(input_size, 0.0);

    for (size_t i = 0; i < input_size; ++i) {
        for (size_t j = 0; j < kernel_size; ++j) {
            if (i >= j) {
                result[i] += input[i - j] * kernel[j];
            }
        }
    }

    return result;
}

void verify_accuracy(const vector<double> &expected, const vector<double> &actual, double tolerance = 0.1) {
    if (expected.size() != actual.size()) {
        cout << "Error: Size mismatch in verification" << endl;
        return;
    }

    double max_error = 0.0;
    for (size_t i = 0; i < expected.size(); i++) {
        double error = fabs(expected[i] - actual[i]);
        if (error > max_error) max_error = error;
    }

    cout << "Verification: Max error = " << max_error;
    if (max_error <= tolerance) {
        cout << " (OK)" << endl;
    } else {
        cout << " (WARNING: Exceeds tolerance)" << endl;
    }
}

int main() {
    try {
        // Set encryption parameters
        EncryptionParameters parms(scheme_type::ckks);
        size_t poly_modulus_degree = 8192;
        parms.set_poly_modulus_degree(poly_modulus_degree);
        parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {40, 36, 32, 28, 24}));

        SEALContext context(parms);
        print_parameters(context);

        // Key generation
        KeyGenerator keygen(context);
        PublicKey public_key;
        keygen.create_public_key(public_key);
        SecretKey secret_key = keygen.secret_key();
        RelinKeys relin_keys = keygen.create_relin_keys();
        GaloisKeys gal_keys = keygen.create_galois_keys();

        Encryptor encryptor(context, public_key);
        Evaluator evaluator(context);
        Decryptor decryptor(context, secret_key);
        CKKSEncoder encoder(context);

        size_t slot_count = encoder.slot_count();
        cout << "Number of slots: " << slot_count << endl;

        // Input signal and kernel
        vector<double> input(slot_count, 0.0);
        vector<double> kernel = {0.2, 0.2, 0.2, 0.2, 0.2}; // Simple averaging filter

        for (size_t i = 0; i < slot_count; ++i)
            input[i] = sin(2 * M_PI * i / slot_count);

        // Encode and encrypt
        double scale = pow(2.0, 24);
        Plaintext plain_input, plain_kernel;
        encoder.encode(input, scale, plain_input);
        encoder.encode(kernel, scale, plain_kernel);

        Ciphertext encrypted_input;
        encryptor.encrypt(plain_input, encrypted_input);

        cout << "\n=== Initial encryption ===" << endl;
        print_noise(decryptor, encrypted_input, "encrypted input");

        // Convolution emulation (simplified: just rotate, multiply, add)
        Ciphertext result;
        for (size_t i = 0; i < kernel.size(); ++i) {
            Ciphertext rotated;
            evaluator.rotate_vector(encrypted_input, i, gal_keys, rotated);
            evaluator.multiply_plain_inplace(rotated, Plaintext()); // Multiply with zero by default
            encoder.encode(kernel[i], scale, plain_kernel);
            evaluator.multiply_plain(rotated, plain_kernel, rotated);
            if (i == 0) {
                result = rotated;
            } else {
                evaluator.add_inplace(result, rotated);
            }
        }

        // Decrypt and decode
        Plaintext plain_result;
        decryptor.decrypt(result, plain_result);
        vector<double> decoded_result;
        encoder.decode(plain_result, decoded_result);

        cout << "\n=== Final Decrypted Result (first 10 values) ===" << endl;
        for (int i = 0; i < 10; ++i)
            cout << decoded_result[i] << " ";
        cout << endl;

        // Compare
        vector<double> expected = simple_convolution(input, kernel);
        verify_accuracy(expected, decoded_result);
    } catch (const exception &e) {
        cerr << "Exception: " << e.what() << endl;
        return 1;
    }

    return 0;
}
