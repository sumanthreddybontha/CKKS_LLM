#include <iostream>
#include <vector>
#include <seal/seal.h>

using namespace std;
using namespace seal;

void setup_seal_context(SEALContext &context, size_t poly_modulus_degree = 8192) {
    EncryptionParameters parms(scheme_type::ckks);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {50, 30, 30, 50}));
    context = SEALContext(parms);
}

void generate_keys(const SEALContext &context, PublicKey &public_key, SecretKey &secret_key, 
                  RelinKeys &relin_keys, GaloisKeys &gal_keys) {
    KeyGenerator keygen(context);
    secret_key = keygen.secret_key();
    keygen.create_public_key(public_key);
    keygen.create_relin_keys(relin_keys);
    keygen.create_galois_keys(gal_keys);
}

vector<vector<double>> prepare_matrix_data(size_t rows, size_t cols) {
    vector<vector<double>> data(rows, vector<double>(cols));
    double val = 0.1;
    for (size_t i = 0; i < rows; i++) {
        for (size_t j = 0; j < cols; j++) {
            data[i][j] = val;
            val += 0.1;
            if (val > 1.0) val = 0.1;
        }
    }
    return data;
}

vector<vector<double>> prepare_kernel_data(size_t rows, size_t cols) {
    vector<vector<double>> data(rows, vector<double>(cols));
    for (size_t i = 0; i < rows; i++) {
        for (size_t j = 0; j < cols; j++) {
            data[i][j] = 0.5 - (0.1 * (i + j));
        }
    }
    return data;
}

int main() {
    // Initialize SEAL
    SEALContext context;
    setup_seal_context(context);
    
    // Generate keys
    PublicKey public_key;
    SecretKey secret_key;
    RelinKeys relin_keys;
    GaloisKeys gal_keys;
    generate_keys(context, public_key, secret_key, relin_keys, gal_keys);
    
    // Create helper objects
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    CKKSEncoder encoder(context);
    size_t slot_count = encoder.slot_count();
    
    // Prepare data
    auto matrix = prepare_matrix_data(10, 10);
    auto kernel = prepare_kernel_data(3, 3);
    
    // Encode and encrypt kernel
    vector<Plaintext> pt_kernel(9);
    vector<Ciphertext> ct_kernel(9);
    for (int i = 0; i < 3; i++) {
        for (int j = 0; j < 3; j++) {
            vector<double> kernel_vec(slot_count, kernel[i][j]);
            encoder.encode(kernel_vec, 1 << 30, pt_kernel[i*3+j]);
            encryptor.encrypt(pt_kernel[i*3+j], ct_kernel[i*3+j]);
        }
    }
    
    // Process matrix in batches
    for (int row = 0; row <= 7; row++) {
        for (int col = 0; col <= 7; col++) {
            Ciphertext dot_product;
            bool first = true;
            
            for (int i = 0; i < 3; i++) {
                for (int j = 0; j < 3; j++) {
                    Plaintext pt_element;
                    encoder.encode(vector<double>(slot_count, matrix[row+i][col+j]), 1 << 30, pt_element);
                    
                    Ciphertext temp;
                    evaluator.multiply_plain(ct_kernel[i*3+j], pt_element, temp);
                    
                    if (first) {
                        dot_product = temp;
                        first = false;
                    } else {
                        evaluator.add_inplace(dot_product, temp);
                    }
                }
            }
            
            // Example decryption for first position
            if (row == 0 && col == 0) {
                Plaintext pt_result;
                decryptor.decrypt(dot_product, pt_result);
                vector<double> result;
                encoder.decode(pt_result, result);
                cout << "First dot product result: " << result[0] << endl;
            }
        }
    }
    
    return 0;
}