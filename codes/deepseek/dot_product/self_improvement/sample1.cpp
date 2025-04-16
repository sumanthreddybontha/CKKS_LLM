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
    cout << "  coeff_modulus: ";
    for (const auto &mod : context_data.parms().coeff_modulus()) {
        cout << mod.value() << " ";
    }
    cout << endl;
}

vector<vector<double>> generate_matrix(size_t rows, size_t cols) {
    vector<vector<double>> matrix(rows, vector<double>(cols));
    for (size_t i = 0; i < rows; i++) {
        for (size_t j = 0; j < cols; j++) {
            matrix[i][j] = static_cast<double>(i + j);
        }
    }
    return matrix;
}

vector<vector<double>> generate_kernel(size_t rows, size_t cols) {
    vector<vector<double>> kernel(rows, vector<double>(cols));
    for (size_t i = 0; i < rows; i++) {
        for (size_t j = 0; j < cols; j++) {
            kernel[i][j] = static_cast<double>(1.0 / (i + j + 1));
        }
    }
    return kernel;
}

int main() {
    // SEAL context setup
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 60}));
    
    SEALContext context(parms);
    print_parameters(context);
    
    // Key generation
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
    
    // Generate data
    auto matrix = generate_matrix(10, 10);
    auto kernel = generate_kernel(3, 3);
    
    // Encode and encrypt matrix and kernel
    vector<Plaintext> plain_kernel(9);
    vector<Ciphertext> encrypted_kernel(9);
    for (int i = 0; i < 3; i++) {
        for (int j = 0; j < 3; j++) {
            vector<double> kernel_vec(slot_count, kernel[i][j]);
            encoder.encode(kernel_vec, 1 << 40, plain_kernel[i*3 + j]);
            encryptor.encrypt(plain_kernel[i*3 + j], encrypted_kernel[i*3 + j]);
        }
    }
    
    // Perform dot product operation for each position
    for (int row = 0; row < 8; row++) {  // 10-3+1 = 8 rows
        for (int col = 0; col < 8; col++) {  // 10-3+1 = 8 cols
            Ciphertext result;
            evaluator.multiply_plain(encrypted_kernel[0], 
                encoder.encode(vector<double>(slot_count, matrix[row][col]), 1 << 40), result);
            
            for (int i = 0; i < 3; i++) {
                for (int j = 0; j < 3; j++) {
                    if (i == 0 && j == 0) continue;
                    
                    Ciphertext temp;
                    evaluator.multiply_plain(encrypted_kernel[i*3 + j], 
                        encoder.encode(vector<double>(slot_count, matrix[row+i][col+j]), 1 << 40), temp);
                    evaluator.add_inplace(result, temp);
                }
            }
            
            // Decrypt and decode one result as example
            if (row == 0 && col == 0) {
                Plaintext plain_result;
                decryptor.decrypt(result, plain_result);
                vector<double> decoded_result;
                encoder.decode(plain_result, decoded_result);
                cout << "Dot product at (0,0): " << decoded_result[0] << endl;
            }
        }
    }
    
    return 0;
}