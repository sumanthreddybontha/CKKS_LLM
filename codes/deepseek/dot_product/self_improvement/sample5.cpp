#include <iostream>
#include <vector>
#include <seal/seal.h>

using namespace std;
using namespace seal;

class CKKS_DotProduct {
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
    size_t slot_count;
    
public:
    CKKS_DotProduct(size_t poly_modulus_degree = 8192) : 
        context(create_context(poly_modulus_degree)),
        encoder(context),
        encryptor(context, public_key),
        evaluator(context),
        decryptor(context, secret_key) {
        
        KeyGenerator keygen(context);
        secret_key = keygen.secret_key();
        keygen.create_public_key(public_key);
        keygen.create_relin_keys(relin_keys);
        keygen.create_galois_keys(gal_keys);
        
        encryptor = Encryptor(context, public_key);
        slot_count = encoder.slot_count();
    }
    
    SEALContext create_context(size_t poly_modulus_degree) {
        EncryptionParameters parms(scheme_type::ckks);
        parms.set_poly_modulus_degree(poly_modulus_degree);
        parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 60}));
        return SEALContext(parms);
    }
    
    vector<vector<double>> create_matrix(size_t rows, size_t cols) {
        vector<vector<double>> matrix(rows, vector<double>(cols));
        for (size_t i = 0; i < rows; i++) {
            for (size_t j = 0; j < cols; j++) {
                matrix[i][j] = sin(i + j);
            }
        }
        return matrix;
    }
    
    vector<vector<double>> create_kernel(size_t rows, size_t cols) {
        vector<vector<double>> kernel(rows, vector<double>(cols));
        for (size_t i = 0; i < rows; i++) {
            for (size_t j = 0; j < cols; j++) {
                kernel[i][j] = cos(i - j);
            }
        }
        return kernel;
    }
    
    void compute_dot_products() {
        auto matrix = create_matrix(10, 10);
        auto kernel = create_kernel(3, 3);
        
        // Encode and encrypt kernel
        vector<Plaintext> pt_kernel(9);
        vector<Ciphertext> ct_kernel(9);
        for (int i = 0; i < 3; i++) {
            for (int j = 0; j < 3; j++) {
                vector<double> kernel_vec(slot_count, kernel[i][j]);
                encoder.encode(kernel_vec, 1 << 40, pt_kernel[i*3+j]);
                encryptor.encrypt(pt_kernel[i*3+j], ct_kernel[i*3+j]);
            }
        }
        
        // Process each 3x3 window
        for (int row = 0; row <= 7; row++) {
            for (int col = 0; col <= 7; col++) {
                Ciphertext window_sum;
                bool first = true;
                
                for (int i = 0; i < 3; i++) {
                    for (int j = 0; j < 3; j++) {
                        Plaintext pt_val;
                        encoder.encode(vector<double>(slot_count, matrix[row+i][col+j]), 1 << 40, pt_val);
                        
                        Ciphertext multiplied;
                        evaluator.multiply_plain(ct_kernel[i*3+j], pt_val, multiplied);
                        
                        if (first) {
                            window_sum = multiplied;
                            first = false;
                        } else {
                            evaluator.add_inplace(window_sum, multiplied);
                        }
                    }
                }
                
                // Decrypt first result as example
                if (row == 0 && col == 0) {
                    Plaintext pt_result;
                    decryptor.decrypt(window_sum, pt_result);
                    vector<double> result;
                    encoder.decode(pt_result, result);
                    cout << "Dot product at (0,0): " << result[0] << endl;
                    
                    // Calculate expected result for verification
                    double expected = 0.0;
                    for (int i = 0; i < 3; i++) {
                        for (int j = 0; j < 3; j++) {
                            expected += matrix[i][j] * kernel[i][j];
                        }
                    }
                    cout << "Expected result: " << expected << endl;
                }
            }
        }
    }
};

int main() {
    CKKS_DotProduct ckks_dot_product;
    ckks_dot_product.compute_dot_products();
    return 0;
}