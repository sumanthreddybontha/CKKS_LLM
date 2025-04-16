#include <iostream>
#include <vector>
#include <chrono>
#include <seal/seal.h>

using namespace std;
using namespace seal;
using namespace std::chrono;

void print_parameters(const SEALContext &context) {
    auto &context_data = *context.key_context_data();
    cout << "Encryption parameters:" << endl;
    cout << "  scheme: CKKS" << endl;
    cout << "  poly_modulus_degree: " << context_data.parms().poly_modulus_degree() << endl;
    cout << "  coeff_modulus size: ";
    for (const auto &mod : context_data.parms().coeff_modulus()) {
        cout << mod.value() << " (" << mod.bit_count() << " bits), ";
    }
    cout << endl;
}

shared_ptr<SEALContext> setup_context(size_t poly_modulus_degree = 16384) {
    EncryptionParameters parms(scheme_type::ckks);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    
    vector<int> bit_sizes = {60, 40, 40, 60};
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, bit_sizes));
    
    shared_ptr<SEALContext> context = make_shared<SEALContext>(parms);
    print_parameters(*context);
    return context;
}

vector<Ciphertext> packed_convolution(
    const CKKSEncoder &encoder, 
    Evaluator &evaluator, 
    const RelinKeys &relin_keys,
    const GaloisKeys &galois_keys,
    const vector<Ciphertext> &packed_inputs,
    const vector<double> &kernel,
    size_t input_size,
    size_t kernel_size,
    double scale) {
    
    size_t poly_modulus_degree = encoder.slot_count();
    vector<Ciphertext> results;
    
    // Encode kernel
    Plaintext kernel_pt;
    encoder.encode(kernel, scale, kernel_pt);
    
    for (const auto &input_ct : packed_inputs) {
        Ciphertext conv_result;
        evaluator.multiply_plain(input_ct, kernel_pt, conv_result);
        evaluator.relinearize_inplace(conv_result, relin_keys);
        evaluator.rescale_to_next_inplace(conv_result);
        
        Ciphertext sum_result = conv_result;
        for (size_t i = 1; i < kernel_size; i++) {
            Ciphertext shifted;
            evaluator.rotate_vector(conv_result, -static_cast<int>(i), galois_keys, shifted);
            evaluator.add_inplace(sum_result, shifted);
        }
        
        results.push_back(sum_result);
    }
    
    return results;
}

vector<double> extract_results(
    const CKKSEncoder &encoder,
    Evaluator &evaluator,
    Decryptor &decryptor,
    const RelinKeys &relin_keys,
    const Ciphertext &packed_result,
    size_t output_size,
    size_t num_parallel_convolutions,
    size_t convolution_idx,
    double scale) {
    
    size_t poly_modulus_degree = encoder.slot_count();
    size_t slots_per_convolution = poly_modulus_degree / num_parallel_convolutions;
    size_t start_slot = convolution_idx * slots_per_convolution;
    
    vector<double> mask(poly_modulus_degree, 0.0);
    for (size_t i = 0; i < output_size; i++) {
        mask[start_slot + i] = 1.0;
    }
    
    Plaintext mask_pt;
    encoder.encode(mask, scale, mask_pt);
    
    Ciphertext masked_result;
    evaluator.multiply_plain(packed_result, mask_pt, masked_result);
    evaluator.relinearize_inplace(masked_result, relin_keys);
    
    Plaintext decrypted;
    decryptor.decrypt(masked_result, decrypted);
    
    vector<double> result;
    encoder.decode(decrypted, result);
    
    vector<double> extracted_result;
    for (size_t i = 0; i < output_size; i++) {
        extracted_result.push_back(result[start_slot + i]);
    }
    
    return extracted_result;
}

int main() {
    try {
        // Setup parameters
        size_t poly_modulus_degree = 16384;
        auto context = setup_context(poly_modulus_degree);
        
        // Create helper objects
        KeyGenerator keygen(*context);
        auto secret_key = keygen.secret_key();
        PublicKey public_key;
        keygen.create_public_key(public_key);
        RelinKeys relin_keys;
        keygen.create_relin_keys(relin_keys);
        GaloisKeys galois_keys;
        keygen.create_galois_keys(galois_keys);
        
        Encryptor encryptor(*context, public_key);
        Evaluator evaluator(*context);
        CKKSEncoder encoder(*context);
        Decryptor decryptor(*context, secret_key);
        
        // Parameters
        size_t input_size = 4096;
        size_t kernel_size = 5;
        size_t output_size = input_size - kernel_size + 1;
        size_t num_inputs = 4;
        size_t num_parallel_convolutions = poly_modulus_degree / input_size;
        double scale = pow(2.0, 40);
        
        cout << "\nNumber of parallel convolutions per ciphertext: " << num_parallel_convolutions << endl;
        
        // Generate random data
        vector<vector<double>> inputs(num_inputs, vector<double>(input_size));
        vector<double> kernel(kernel_size);
        
        for (auto &input : inputs) {
            for (auto &val : input) {
                val = static_cast<double>(rand()) / RAND_MAX;
            }
        }
        
        for (auto &val : kernel) {
            val = static_cast<double>(rand()) / RAND_MAX;
        }
        
        // Pack inputs
        vector<Ciphertext> packed_inputs;
        for (size_t i = 0; i < num_inputs; i += num_parallel_convolutions) {
            vector<double> packed_data(poly_modulus_degree, 0.0);
            
            for (size_t j = 0; j < min(num_parallel_convolutions, num_inputs - i); j++) {
                size_t start_pos = j * input_size;
                copy(inputs[i + j].begin(), inputs[i + j].end(), packed_data.begin() + start_pos);
            }
            
            Plaintext pt;
            encoder.encode(packed_data, scale, pt);
            Ciphertext ct;
            encryptor.encrypt(pt, ct);
            packed_inputs.push_back(ct);
        }
        
        // Run packed convolution
        cout << "\nRunning packed convolution..." << endl;
        auto start_packed = high_resolution_clock::now();
        auto packed_results = packed_convolution(
            encoder, evaluator, relin_keys, galois_keys, 
            packed_inputs, kernel, input_size, kernel_size, scale);
        auto stop_packed = high_resolution_clock::now();
        
        // Extract results
        size_t convolution_to_extract = 1;
        cout << "Extracting results..." << endl;
        auto extracted_results = extract_results(
            encoder, evaluator, decryptor, relin_keys, packed_results[0],
            output_size, num_parallel_convolutions, convolution_to_extract, scale);
        
        cout << "\nFirst 5 extracted results: ";
        for (int i = 0; i < 5 && i < extracted_results.size(); i++) {
            cout << extracted_results[i] << " ";
        }
        cout << endl;
        
        auto packed_duration = duration_cast<milliseconds>(stop_packed - start_packed);
        cout << "\nPacked convolution completed in " << packed_duration.count() << " ms" << endl;
        
    } catch (const exception &e) {
        cerr << "\nError: " << e.what() << endl;
        return 1;
    }
    
    return 0;
}