#include <iostream>
#include <vector>
#include <chrono>
#include <seal/seal.h>

using namespace std;
using namespace seal;

// Function to print matrix
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

// Function to generate random matrix
vector<vector<double>> generate_random_matrix(size_t rows, size_t cols, double min = 0.0, double max = 1.0) {
    vector<vector<double>> matrix(rows, vector<double>(cols));
    for (size_t i = 0; i < rows; i++) {
        for (size_t j = 0; j < cols; j++) {
            matrix[i][j] = min + static_cast<double>(rand()) / (static_cast<double>(RAND_MAX/(max-min)));
        }
    }
    return matrix;
}

// Function to print SEAL context parameters
void print_parameters_info(const SEALContext &context) {
    auto &context_data = *context.key_context_data();
    cout << "\nParameters used:" << endl;
    cout << "Scheme: CKKS" << endl;
    cout << "Poly modulus degree: " << context_data.parms().poly_modulus_degree() << endl;
    cout << "Coeff modulus size: " << context_data.parms().coeff_modulus().size() << endl;
    cout << "Coeff modulus bits: [";
    for (const auto &mod : context_data.parms().coeff_modulus()) {
        cout << mod.bit_count() << " ";
    }
    cout << "]" << endl << endl;
}

int main() {
    // Set up parameters
    size_t poly_modulus_degree = 8192;
    vector<int> modulus_bits = {60, 40, 40, 60};  // Primes for modulus chain
    size_t scale_power = 40;
    double scale = pow(2.0, scale_power);

    // Matrix dimensions (must be power of 2 for simplicity)
    size_t matrix_size = 4;  // 4x4 matrices
    size_t slot_count = poly_modulus_degree / 2;

    cout << "Matrix multiplication using CKKS" << endl;
    cout << "Matrix size: " << matrix_size << "x" << matrix_size << endl;
    cout << "Poly modulus degree: " << poly_modulus_degree << endl;
    cout << "Slot count: " << slot_count << endl << endl;

    // Generate random matrices
    auto matrix1 = generate_random_matrix(matrix_size, matrix_size, 0.0, 1.0);
    auto matrix2 = generate_random_matrix(matrix_size, matrix_size, 0.0, 1.0);

    cout << "Matrix A:" << endl;
    print_matrix(matrix1);
    cout << "Matrix B:" << endl;
    print_matrix(matrix2);

    // Step 1: Initialize SEAL context
    EncryptionParameters params(scheme_type::ckks);
    params.set_poly_modulus_degree(poly_modulus_degree);
    params.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, modulus_bits));

    SEALContext context(params);
    print_parameters_info(context);

    // Step 2: Generate keys
    KeyGenerator keygen(context);
    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys gal_keys;
    keygen.create_galois_keys(gal_keys);

    // Step 3: Set up encryptor, evaluator, decryptor
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    // Step 4: Create CKKS encoder
    CKKSEncoder encoder(context);

    // Step 5: Encode and encrypt matrices
    vector<Plaintext> plain_matrix1(matrix_size);
    vector<Plaintext> plain_matrix2(matrix_size);
    vector<Ciphertext> encrypted_matrix1(matrix_size);
    vector<Ciphertext> encrypted_matrix2(matrix_size);

    // Encode and encrypt matrix1
    for (size_t i = 0; i < matrix_size; i++) {
        encoder.encode(matrix1[i], scale, plain_matrix1[i]);
        encryptor.encrypt(plain_matrix1[i], encrypted_matrix1[i]);
    }

    // Encode and encrypt matrix2 (column-wise for efficient multiplication)
    vector<vector<double>> matrix2_transposed(matrix_size, vector<double>(matrix_size));
    for (size_t i = 0; i < matrix_size; i++) {
        for (size_t j = 0; j < matrix_size; j++) {
            matrix2_transposed[j][i] = matrix2[i][j];
        }
    }

    for (size_t i = 0; i < matrix_size; i++) {
        encoder.encode(matrix2_transposed[i], scale, plain_matrix2[i]);
        encryptor.encrypt(plain_matrix2[i], encrypted_matrix2[i]);
    }

    // Step 6: Perform matrix multiplication
    vector<Ciphertext> encrypted_result(matrix_size);
    Plaintext plain_result;
    vector<double> result_row;

    auto start_time = chrono::high_resolution_clock::now();

    for (size_t i = 0; i < matrix_size; i++) {
        evaluator.multiply_plain(encrypted_matrix1[i], plain_matrix2[0], encrypted_result[i]);
        
        for (size_t j = 1; j < matrix_size; j++) {
            Ciphertext temp;
            evaluator.multiply_plain(encrypted_matrix1[i], plain_matrix2[j], temp);
            evaluator.add_inplace(encrypted_result[i], temp);
        }
    }

    auto end_time = chrono::high_resolution_clock::now();
    auto duration = chrono::duration_cast<chrono::milliseconds>(end_time - start_time);
    cout << "Matrix multiplication done in " << duration.count() << " milliseconds" << endl << endl;

    // Step 7: Decrypt and decode results
    vector<vector<double>> result(matrix_size, vector<double>(matrix_size));
    for (size_t i = 0; i < matrix_size; i++) {
        decryptor.decrypt(encrypted_result[i], plain_result);
        encoder.decode(plain_result, result_row);
        
        // Extract the first matrix_size elements as our result
        for (size_t j = 0; j < matrix_size; j++) {
            result[i][j] = result_row[j];
        }
    }

    // Step 8: Compute plaintext result for comparison
    vector<vector<double>> plain_result_matrix(matrix_size, vector<double>(matrix_size));
    for (size_t i = 0; i < matrix_size; i++) {
        for (size_t j = 0; j < matrix_size; j++) {
            plain_result_matrix[i][j] = 0.0;
            for (size_t k = 0; k < matrix_size; k++) {
                plain_result_matrix[i][j] += matrix1[i][k] * matrix2[k][j];
            }
        }
    }

    // Step 9: Print and compare results
    cout << "Encrypted result:" << endl;
    print_matrix(result);

    cout << "Plaintext result:" << endl;
    print_matrix(plain_result_matrix);

    // Calculate and print the error
    double max_error = 0.0;
    for (size_t i = 0; i < matrix_size; i++) {
        for (size_t j = 0; j < matrix_size; j++) {
            double error = abs(result[i][j] - plain_result_matrix[i][j]);
            if (error > max_error) {
                max_error = error;
            }
        }
    }
    cout << "Maximum error: " << max_error << endl;

    return 0;
}