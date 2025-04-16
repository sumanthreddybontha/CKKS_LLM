#include <iostream>
#include <vector>
#include <complex>
#include <numeric>
#include <seal/seal.h>

using namespace std;
using namespace seal;

void print_parameters(const SEALContext &context) {
    auto &context_data = *context.key_context_data();
    cout << "\n/ Encryption parameters:" << endl;
    cout << "| scheme: CKKS" << endl;
    cout << "| poly_modulus_degree: " << context_data.parms().poly_modulus_degree() << endl;
    cout << "| coeff_modulus size: ";
    cout << context_data.parms().coeff_modulus().size() << " (";
    for (size_t i = 0; i < context_data.parms().coeff_modulus().size(); i++) {
        cout << context_data.parms().coeff_modulus()[i].bit_count();
        if (i < context_data.parms().coeff_modulus().size() - 1)
            cout << " + ";
    }
    cout << ") bits" << endl;
    cout << "\\ scale: 2^" << log2(context_data.parms().coeff_modulus().back().value()) << endl;
}

void print_noise(const Decryptor &decryptor, const Ciphertext &ciphertext, const string &tag) {
    cout << "Noise budget in " << tag << ": " 
         << decryptor.invariant_noise_budget(ciphertext) << " bits" << endl;
}

void verify_accuracy(const vector<double> &expected, const vector<double> &actual, double tolerance = 0.1) {
    if (expected.size() != actual.size()) {
        cout << "Error: Size mismatch in verification" << endl;
        return;
    }
    
    double max_error = 0.0;
    for (size_t i = 0; i < expected.size(); i++) {
        double error = abs(expected[i] - actual[i]);
        if (error > max_error) max_error = error;
    }
    
    cout << "Verification: Max error = " << max_error;
    if (max_error <= tolerance) {
        cout << " (OK)" << endl;
    } else {
        cout << " (WARNING: Exceeds tolerance)" << endl;
    }
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

int main() {
    try {
        // Set up parameters
        EncryptionParameters parms(scheme_type::ckks);
        size_t poly_modulus_degree = 8192;
        parms.set_poly_modulus_degree(poly_modulus_degree);
        
        // 5-level modulus chain: 40-36-32-28-24 bits
        vector<int> bit_sizes = {40, 36, 32, 28, 24};
        parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, bit_sizes));
        
        SEALContext context(parms);
        print_parameters(context);
        
        // Generate keys
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
        
        // Set up initial scale
        double scale = pow(2.0, 12);
        
        // Input data and kernel
        vector<double> input(slot_count, 0.0);
        vector<double> kernel(5, 0.0);
        
        // Fill input with some values
        for (size_t i = 0; i < slot_count; i++) {
            input[i] = sin(2 * 3.14159265 * i / slot_count);
        }
        
        // Fill kernel (e.g., simple averaging filter)
        for (size_t i = 0; i < kernel.size(); i++) {
            kernel[i] = 0.2; // Simple averaging filter
        }
        
        // Plaintext versions
        Plaintext plain_input, plain_kernel;
        encoder.encode(input, scale, plain_input);
        encoder.encode(kernel, scale, plain_kernel);
        
        // Encrypt
        Ciphertext encrypted_input;
        encryptor.encrypt(plain_input, encrypted_input);
        
        cout << "\n=== Initial encryption ===" << endl;
        print_noise(decryptor, encrypted_input, "encrypted input");
        
        // Perform convolution with depth 3
        for (int conv_step = 0; conv_step < 3; conv_step++) {
            cout << "\n=== Convolution Step " << (conv_step + 1) << " ===" << endl;
            
            // Rotate and multiply
            Ciphertext rotated, product;
            evaluator.rotate_vector(encrypted_input, 1, gal_keys, rotated);
            
            cout << "\nAfter rotation:" << endl;
            print_noise(decryptor, rotated, "rotated ciphertext");
            
            evaluator.multiply(rotated, plain_kernel, product);
            evaluator.relinearize_inplace(product, relin_keys);
            
            cout << "\nAfter multiplication:" << endl;
            print_noise(decryptor, product, "product ciphertext");
            
            // Modulus switching
            int noise_before = decryptor.invariant_noise_budget(product);
            evaluator.mod_switch_to_next_inplace(product);
            int noise_after = decryptor.invariant_noise_budget(product);
            
            cout << "\nAfter modulus switching:" << endl;
            print_noise(decryptor, product, "mod-switched ciphertext");
            cout << "Noise budget change: " << (noise_after - noise_before) << " bits" << endl;
            
            // Rescale
            noise_before = decryptor.invariant_noise_budget(product);
            evaluator.rescale_to_next_inplace(product);
            noise_after = decryptor.invariant_noise_budget(product);
            
            cout << "\nAfter rescaling:" << endl;
            print_noise(decryptor, product, "rescaled ciphertext");
            cout << "Noise budget change: " << (noise_after - noise_before) << " bits" << endl;
            
            // Verify accuracy
            Plaintext plain_result;
            vector<double> result;
            decryptor.decrypt(product, plain_result);
            encoder.decode(plain_result, result);
            
            // Compute expected result
            vector<double> expected = simple_convolution(input, kernel);
            verify_accuracy(expected, result);
            
            // Add to accumulator
            if (conv_step == 0) {
                encrypted_input = product;
            } else {
                evaluator.add_inplace(encrypted_input, product);
            }
            
            cout << "\nAfter accumulation:" << endl;
            print_noise(decryptor, encrypted_input, "accumulated ciphertext");
        }
        
        // Final result
        Plaintext plain_final;
        vector<double> final_result;
        decryptor.decrypt(encrypted_input, plain_final);
        encoder.decode(plain_final, final_result);
        
        cout << "\n=== Final Result ===" << endl;
        cout << "First 10 values:" << endl;
        for (int i = 0; i < 10; i++) {
            cout << final_result[i] << " ";
        }
        cout << endl;
        
        return 0;
    } catch (const exception &e) {
        cerr << "Error: " << e.what() << endl;
        return -1;
    }
}