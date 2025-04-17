#include <iostream>
#include <vector>
#include <cmath>
#include <seal/seal.h>

using namespace std;
using namespace seal;

// Helper: Pretty-print matrix
void print_matrix(const vector<vector<double>> &matrix) {
    for (const auto &row : matrix) {
        cout << "[ ";
        for (auto val : row) cout << val << " ";
        cout << "]\n";
    }
    cout << endl;
}

// Create sample matrix
vector<vector<double>> create_matrix(size_t rows, size_t cols, double start = 1.0, double step = 1.0) {
    vector<vector<double>> mat(rows, vector<double>(cols));
    double val = start;
    for (auto &row : mat)
        for (auto &cell : row)
            cell = val, val += step;
    return mat;
}

// Print SEAL context parameters
void print_seal_params(const SEALContext &context) {
    auto &parms = context.first_context_data()->parms();
    cout << "Encryption parameters:\n";
    cout << "- poly_modulus_degree: " << parms.poly_modulus_degree() << endl;
    cout << "- coeff_modulus size: ";
    for (const auto &q : parms.coeff_modulus()) cout << q.bit_count() << " ";
    cout << "bits\n" << endl;
}

// Main CKKS Matrix Multiplication Logic
void ckks_matrix_mult() {
    // Step 1: Setup SEAL CKKS parameters
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 60}));

    SEALContext context(parms);
    print_seal_params(context);

    // Step 2: Key generation
    KeyGenerator keygen(context);
    PublicKey public_key;
    SecretKey secret_key = keygen.secret_key();
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
    double scale = pow(2.0, 40);
    cout << "Number of CKKS slots available: " << slot_count << endl;

    // Step 3: Create example matrices (2x3 × 3x2)
    auto A = create_matrix(2, 3);  // 2x3
    auto B = create_matrix(3, 2);  // 3x2
    cout << "Matrix A:\n"; print_matrix(A);
    cout << "Matrix B:\n"; print_matrix(B);

    // Step 4: Encrypt rows of A
    vector<Ciphertext> enc_rows_A;
    for (const auto &row : A) {
        vector<double> row_packed(slot_count, 0.0);
        copy(row.begin(), row.end(), row_packed.begin());
        Plaintext pt;
        encoder.encode(row_packed, scale, pt);
        Ciphertext ct;
        encryptor.encrypt(pt, ct);
        enc_rows_A.push_back(ct);
    }

    // Step 5: Encrypt columns of B (transposed)
    vector<Ciphertext> enc_cols_B;
    for (size_t col = 0; col < B[0].size(); ++col) {
        vector<double> col_data(slot_count, 0.0);
        for (size_t row = 0; row < B.size(); ++row)
            col_data[row] = B[row][col];
        Plaintext pt;
        encoder.encode(col_data, scale, pt);
        Ciphertext ct;
        encryptor.encrypt(pt, ct);
        enc_cols_B.push_back(ct);
    }

    // Step 6: Perform Encrypted Dot Products
    vector<vector<Ciphertext>> enc_result(2, vector<Ciphertext>(2));

    for (size_t i = 0; i < 2; i++) {
        for (size_t j = 0; j < 2; j++) {
            Ciphertext mult;
            evaluator.multiply(enc_rows_A[i], enc_cols_B[j], mult);
            evaluator.relinearize_inplace(mult, relin_keys);
            evaluator.rescale_to_next_inplace(mult);

            // Align scales & levels before summation
            Ciphertext sum = mult;
            for (size_t k = 1; k < 3; k <<= 1) {
                Ciphertext rotated;
                evaluator.rotate_vector(sum, k, gal_keys, rotated);
                evaluator.add_inplace(sum, rotated);
            }

            enc_result[i][j] = sum;
        }
    }

    // Step 7: Decrypt & decode result
    vector<vector<double>> result(2, vector<double>(2));
    for (size_t i = 0; i < 2; i++) {
        for (size_t j = 0; j < 2; j++) {
            Plaintext pt;
            decryptor.decrypt(enc_result[i][j], pt);
            vector<double> decoded;
            encoder.decode(pt, decoded);
            result[i][j] = decoded[0]; // First slot holds dot product
        }
    }

    cout << "\nDecrypted Encrypted Result:\n";
    print_matrix(result);

    // Step 8: Plaintext matrix multiplication to verify
    vector<vector<double>> expected(2, vector<double>(2, 0.0));
    for (size_t i = 0; i < 2; i++)
        for (size_t j = 0; j < 2; j++)
            for (size_t k = 0; k < 3; k++)
                expected[i][j] += A[i][k] * B[k][j];

    cout << "Expected Plaintext Result:\n";
    print_matrix(expected);

    // Step 9: Compare with tolerance
    cout << "Comparison (tolerance = 0.01):\n";
    for (size_t i = 0; i < 2; i++) {
        for (size_t j = 0; j < 2; j++) {
            double err = fabs(result[i][j] - expected[i][j]);
            cout << "[" << (err < 0.01 ? "OK" : "❌") << " error=" << err << "] ";
        }
        cout << endl;
    }
}

int main() {
    try {
        ckks_matrix_mult();
    } catch (const exception &e) {
        cerr << "Exception: " << e.what() << endl;
        return 1;
    }
    return 0;
}