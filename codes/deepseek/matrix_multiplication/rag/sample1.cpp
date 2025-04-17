#include <iostream>
#include <vector>
#include <cmath>
#include <chrono>
#include <seal/seal.h>

using namespace std;
using namespace seal;

void print_matrix(const vector<vector<double>> &matrix, size_t row_count = 4, size_t col_count = 4) {
    for (size_t i = 0; i < min(row_count, matrix.size()); i++) {
        cout << "[ ";
        for (size_t j = 0; j < min(col_count, matrix[i].size()); j++) {
            cout << matrix[i][j] << ((j != min(col_count, matrix[i].size()) - 1) ? ", " : " ]\n");
        }
    }
    cout << endl;
}

void ckks_matrix_multiplication() {
    // Parameters
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));
    double scale = pow(2.0, 40);

    SEALContext context(parms);
    CKKSEncoder encoder(context);
    size_t slot_count = encoder.slot_count();

    cout << "\nCKKS Parameters:\n";
    cout << "- poly_modulus_degree: " << poly_modulus_degree << "\n";
    cout << "- coeff_modulus sizes (bits): ";
    for (auto &mod : parms.coeff_modulus()) cout << mod.bit_count() << " ";
    cout << "\n- slot_count: " << slot_count << "\n\n";

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

    // Matrices
    vector<vector<double>> matrix1 = {{1, 2, 3}, {4, 5, 6}};
    vector<vector<double>> matrix2 = {{7, 8}, {9, 10}, {11, 12}};
    vector<vector<double>> expected = {{58, 64}, {139, 154}};

    cout << "Matrix 1:\n"; print_matrix(matrix1);
    cout << "Matrix 2:\n"; print_matrix(matrix2);
    cout << "Expected Result:\n"; print_matrix(expected);

    // Encrypt matrix1 rows
    vector<Ciphertext> encrypted_matrix1;
    for (auto &row : matrix1) {
        Plaintext plain_row;
        encoder.encode(row, scale, plain_row);
        Ciphertext enc_row;
        encryptor.encrypt(plain_row, enc_row);
        encrypted_matrix1.push_back(enc_row);
    }

    // Encode matrix2 columns
    vector<Plaintext> encoded_matrix2_cols;
    for (size_t j = 0; j < matrix2[0].size(); j++) {
        vector<double> column(matrix2.size());
        for (size_t i = 0; i < matrix2.size(); i++)
            column[i] = matrix2[i][j];

        Plaintext pt;
        encoder.encode(column, scale, pt);
        encoded_matrix2_cols.push_back(pt);
    }

    // Multiply
    vector<Ciphertext> encrypted_result;
    auto start = chrono::high_resolution_clock::now();

    for (size_t i = 0; i < encrypted_matrix1.size(); i++) {
        for (size_t j = 0; j < encoded_matrix2_cols.size(); j++) {
            Ciphertext temp;
            evaluator.multiply_plain(encrypted_matrix1[i], encoded_matrix2_cols[j], temp);
            evaluator.relinearize_inplace(temp, relin_keys);
            evaluator.rescale_to_next_inplace(temp);

            // Sum elements (dot product)
            Ciphertext sum = temp;
            size_t rotations = matrix1[0].size();
            for (size_t k = 1; k < rotations; k <<= 1) {
                Ciphertext rotated;
                evaluator.rotate_vector(sum, k, gal_keys, rotated);
                evaluator.add_inplace(sum, rotated);
            }

            encrypted_result.push_back(sum);
        }
    }

    auto end = chrono::high_resolution_clock::now();
    cout << "Homomorphic multiplication time: " 
         << chrono::duration_cast<chrono::milliseconds>(end - start).count() 
         << " ms\n\n";

    // Decrypt & decode
    vector<vector<double>> result_matrix(matrix1.size(), vector<double>(matrix2[0].size()));
    size_t idx = 0;
    for (size_t i = 0; i < matrix1.size(); i++) {
        for (size_t j = 0; j < matrix2[0].size(); j++) {
            Plaintext plain_result;
            decryptor.decrypt(encrypted_result[idx++], plain_result);

            vector<double> decoded;
            encoder.decode(plain_result, decoded);
            result_matrix[i][j] = decoded[0]; // First slot = dot product
        }
    }

    cout << "Computed Result:\n";
    print_matrix(result_matrix);

    // Compare with expected
    double max_err = 0.0, avg_err = 0.0;
    size_t count = 0;
    cout << "Comparison (tolerance = 0.1):\n";
    for (size_t i = 0; i < expected.size(); i++) {
        for (size_t j = 0; j < expected[0].size(); j++) {
            double diff = abs(expected[i][j] - result_matrix[i][j]);
            cout << "[" << (diff < 0.1 ? "OK" : "❌") << " err=" << diff << "] ";
            max_err = max(max_err, diff);
            avg_err += diff;
            count++;
        }
        cout << endl;
    }

    avg_err /= count;
    cout << "\n✅ Average error: " << avg_err << "\n";
    cout << "✅ Max error: " << max_err << "\n";
    cout << "✅ Final Verdict: " << ((max_err < 0.1) ? "PASS ✅" : "FAIL ❌") << endl;
}

int main() {
    try {
        ckks_matrix_multiplication();
    } catch (const exception &e) {
        cerr << "Error: " << e.what() << endl;
        return 1;
    }
    return 0;
}