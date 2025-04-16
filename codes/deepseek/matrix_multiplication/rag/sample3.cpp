#include <iostream>
#include <vector>
#include <seal/seal.h>

using namespace std;
using namespace seal;

// Helper function to print matrix
void print_matrix(const vector<vector<double>> &matrix, size_t row_count = 4, size_t col_count = 4) {
    for (size_t i = 0; i < min(row_count, matrix.size()); i++) {
        cout << "[ ";
        for (size_t j = 0; j < min(col_count, matrix[i].size()); j++) {
            cout << matrix[i][j] << " ";
        }
        cout << "]" << endl;
    }
    cout << endl;
}

// CKKS Matrix Multiplication
void ckks_matrix_multiplication() {
    // Set up encryption parameters
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    
    // Custom coefficient modulus for CKKS (adjust based on security and precision needs)
    vector<int> modulus_bits = {60, 40, 40, 60};  // Total of 200 bits
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, modulus_bits));
    
    double scale = pow(2.0, 40);

    // Create SEAL context
    SEALContext context(parms);
    cout << endl;

    // Generate keys
    KeyGenerator keygen(context);
    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys gal_keys;
    keygen.create_galois_keys(gal_keys);

    // Set up encryptor, evaluator, decryptor
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    CKKSEncoder encoder(context);

    // Define matrix dimensions (must be power of 2 for simplicity)
    const size_t mat_size = 4;  // 4x4 matrices
    const size_t slot_count = encoder.slot_count();
    
    // Create sample matrices
    vector<vector<double>> matrix1(mat_size, vector<double>(mat_size));
    vector<vector<double>> matrix2(mat_size, vector<double>(mat_size));
    
    // Fill matrices with sample values
    double val1 = 1.0, val2 = 1.0;
    for (size_t i = 0; i < mat_size; i++) {
        for (size_t j = 0; j < mat_size; j++) {
            matrix1[i][j] = val1++;
            matrix2[i][j] = val2++;
        }
    }

    cout << "Matrix A:" << endl;
    print_matrix(matrix1);
    cout << "Matrix B:" << endl;
    print_matrix(matrix2);

    // Encode and encrypt matrix1 (row-wise)
    vector<Plaintext> encoded_matrix1(mat_size);
    vector<Ciphertext> encrypted_matrix1(mat_size);
    for (size_t i = 0; i < mat_size; i++) {
        encoder.encode(matrix1[i], scale, encoded_matrix1[i]);
        encryptor.encrypt(encoded_matrix1[i], encrypted_matrix1[i]);
    }

    // Encode matrix2 (column-wise) - no need to encrypt for this demonstration
    vector<Plaintext> encoded_matrix2(mat_size);
    for (size_t j = 0; j < mat_size; j++) {
        vector<double> column(mat_size);
        for (size_t i = 0; i < mat_size; i++) {
            column[i] = matrix2[i][j];
        }
        encoder.encode(column, scale, encoded_matrix2[j]);
    }

    // Perform matrix multiplication
    vector<Ciphertext> encrypted_result(mat_size);
    for (size_t i = 0; i < mat_size; i++) {
        // Initialize result ciphertext with first multiplication
        evaluator.multiply_plain(encrypted_matrix1[i], encoded_matrix2[0], encrypted_result[i]);
        evaluator.rescale_to_next_inplace(encrypted_result[i]);
        
        // Accumulate the rest of the multiplications
        for (size_t j = 1; j < mat_size; j++) {
            Ciphertext temp;
            evaluator.multiply_plain(encrypted_matrix1[i], encoded_matrix2[j], temp);
            evaluator.rescale_to_next_inplace(temp);
            
            // Align scales before adding
            evaluator.mod_switch_to_inplace(encrypted_result[i], temp.parms_id());
            evaluator.add_inplace(encrypted_result[i], temp);
        }
    }

    // Decrypt and decode results
    vector<vector<double>> result(mat_size, vector<double>(mat_size));
    for (size_t i = 0; i < mat_size; i++) {
        Plaintext plain_result;
        decryptor.decrypt(encrypted_result[i], plain_result);
        
        vector<double> row_result;
        encoder.decode(plain_result, row_result);
        
        for (size_t j = 0; j < mat_size; j++) {
            result[i][j] = row_result[j];
        }
    }

    cout << "Result of AxB:" << endl;
    print_matrix(result);
}

int main() {
    try {
        ckks_matrix_multiplication();
    } catch (const exception &e) {
        cerr << "Error: " << e.what() << endl;
        return -1;
    }
    return 0;
}