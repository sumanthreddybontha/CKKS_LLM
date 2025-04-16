#include <iostream>
#include <vector>
#include <seal/seal.h>
#include <chrono>

using namespace std;
using namespace seal;
using namespace std::chrono;

struct CKKSConfig {
    size_t poly_modulus_degree = 16384;  // Larger poly modulus for more operations
    vector<int> coeff_modulus_bits = {50, 30, 30, 30, 50};  // More primes for deeper computations
    double scale = pow(2.0, 40);
};

class ParallelCKKSProcessor {
private:
    SEALContext context;
    CKKSEncoder encoder;
    Encryptor encryptor;
    Evaluator evaluator;
    Decryptor decryptor;
    PublicKey public_key;
    SecretKey secret_key;
    RelinKeys relin_keys;
    GaloisKeys gal_keys;
    CKKSConfig config;
    size_t slot_count;
    
public:
    ParallelCKKSProcessor(const CKKSConfig &cfg) : config(cfg), 
        context(create_context(config.poly_modulus_degree, config.coeff_modulus_bits)),
        encoder(context),
        encryptor(context, public_key),
        evaluator(context),
        decryptor(context, secret_key) {
        
        // Key generation
        KeyGenerator keygen(context);
        secret_key = keygen.secret_key();
        keygen.create_public_key(public_key);
        keygen.create_relin_keys(relin_keys);
        keygen.create_galois_keys(gal_keys);
        
        slot_count = encoder.slot_count();
        cout << "Number of slots: " << slot_count << endl;
    }
    
    SEALContext create_context(size_t poly_modulus_degree, const vector<int> &coeff_modulus_bits) {
        EncryptionParameters parms(scheme_type::ckks);
        parms.set_poly_modulus_degree(poly_modulus_degree);
        parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, coeff_modulus_bits));
        return SEALContext(parms);
    }
    
    vector<vector<double>> generate_random_matrix(size_t rows, size_t cols) {
        vector<vector<double>> matrix(rows, vector<double>(cols));
        for (size_t i = 0; i < rows; i++) {
            for (size_t j = 0; j < cols; j++) {
                matrix[i][j] = static_cast<double>(rand()) / RAND_MAX;
            }
        }
        return matrix;
    }
    
    vector<vector<double>> generate_gaussian_kernel(size_t size, double sigma = 1.0) {
        vector<vector<double>> kernel(size, vector<double>(size));
        double sum = 0.0;
        int center = size / 2;
        
        for (int i = 0; i < size; i++) {
            for (int j = 0; j < size; j++) {
                double x = i - center;
                double y = j - center;
                kernel[i][j] = exp(-(x*x + y*y) / (2 * sigma * sigma));
                sum += kernel[i][j];
            }
        }
        
        // Normalize
        for (int i = 0; i < size; i++) {
            for (int j = 0; j < size; j++) {
                kernel[i][j] /= sum;
            }
        }
        
        return kernel;
    }
    
    void process_convolution() {
        auto matrix = generate_random_matrix(10, 10);
        auto kernel = generate_gaussian_kernel(3);
        
        // Encrypt kernel elements
        vector<Ciphertext> encrypted_kernel(9);
        for (int i = 0; i < 3; i++) {
            for (int j = 0; j < 3; j++) {
                Plaintext pt_kernel;
                encoder.encode(vector<double>(slot_count, kernel[i][j]), config.scale, pt_kernel);
                encryptor.encrypt(pt_kernel, encrypted_kernel[i*3 + j]);
            }
        }
        
        // Process each window position
        auto start = high_resolution_clock::now();
        
        for (int row = 0; row <= 7; row++) {
            for (int col = 0; col <= 7; col++) {
                Ciphertext window_result;
                bool first = true;
                
                for (int i = 0; i < 3; i++) {
                    for (int j = 0; j < 3; j++) {
                        Plaintext pt_matrix_val;
                        encoder.encode(vector<double>(slot_count, matrix[row+i][col+j]), config.scale, pt_matrix_val);
                        
                        Ciphertext temp;
                        evaluator.multiply_plain(encrypted_kernel[i*3 + j], pt_matrix_val, temp);
                        
                        if (first) {
                            window_result = temp;
                            first = false;
                        } else {
                            evaluator.add_inplace(window_result, temp);
                        }
                    }
                }
                
                // For demonstration, decrypt the first result
                if (row == 0 && col == 0) {
                    Plaintext pt_result;
                    decryptor.decrypt(window_result, pt_result);
                    vector<double> result;
                    encoder.decode(pt_result, result);
                    
                    cout << "First window result: " << result[0] << endl;
                    
                    // Compute expected value
                    double expected = 0.0;
                    for (int i = 0; i < 3; i++) {
                        for (int j = 0; j < 3; j++) {
                            expected += matrix[i][j] * kernel[i][j];
                        }
                    }
                    cout << "Expected value: " << expected << endl;
                    cout << "Absolute error: " << abs(result[0] - expected) << endl;
                }
            }
        }
        
        auto stop = high_resolution_clock::now();
        auto duration = duration_cast<milliseconds>(stop - start);
        cout << "Total computation time: " << duration.count() << " ms" << endl;
    }
};

int main() {
    CKKSConfig config;
    config.poly_modulus_degree = 8192;  // Reduced for faster execution
    config.coeff_modulus_bits = {40, 30, 40};
    
    ParallelCKKSProcessor processor(config);
    processor.process_convolution();
    
    return 0;
}