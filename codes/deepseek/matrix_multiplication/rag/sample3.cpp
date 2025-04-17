#include <iostream>
#include <vector>
#include <seal/seal.h>

using namespace std;
using namespace seal;

// Helper: Print a matrix
void print_matrix(const vector<vector<double>> &matrix) {
    for (const auto &row : matrix) {
        cout << "[ ";
        for (auto val : row) cout << val << " ";
        cout << "]\n";
    }
    cout << endl;
}

// Generate simple square matrices with incremental values
vector<vector<double>> generate_matrix(size_t size, double start_val = 1.0) {
    vector<vector<double>> mat(size, vector<double>(size));
    double val = start_val;
    for (auto &row : mat)
        for (auto &cell : row)
            cell = val++;
    return mat;
}

void ckks_matrix_multiplication() {
    // === SEAL Setup ===
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 60}));

    SEALContext context(parms);
    cout << "Encryption parameters:\n";
    cout << " - poly_modulus_degree: " << poly_modulus_degree << "\n";
    cout << " - coeff_modulus: ";
    for (auto &mod : parms.coeff_modulus()) cout << mod.bit_count() << " ";
    cout << "bits\n\n";

    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys gal_keys;
    keygen.create_galois_keys(gal_keys);

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    CKKSEncoder encoder(context);
    double scale = pow(2.0, 40);
    size_t slot_count = encoder.slot_count();

    // === Matrix Setup ===
    const size_t size = 4;
    auto A = generate_matrix(size, 1.0);
    auto B = generate_matrix(size, 1.0);

    cout << "Matrix A:\n"; print_matrix(A);
    cout << "Matrix B:\n"; print_matrix(B);

    // === Encrypt rows of A ===
    vector<Ciphertext> encrypted_rows_A(size);
    for (size_t i = 0; i < size; i++) {
        vector<double> row(slot_count, 0.0);
        for (size_t j = 0; j < size; j++) row[j] = A[i][j];
        Plaintext plain;
        encoder.encode(row, scale, plain);
        encryptor.encrypt(plain, encrypted_rows_A[i]);
    }

    // === Encode columns of B ===
    vector<Plaintext> encoded_cols_B(size);
    for (size_t j = 0; j < size; j++) {
        vector<double> col(slot_count, 0.0);
        for (size_t i = 0; i < size; i++) col[i] = B[i][j];
        encoder.encode(col, scale, encoded_cols_B[j]);
    }

    // === Perform encrypted dot product row(A) · col(B) ===
    vector<vector<Ciphertext>> encrypted_result(size, vector<Ciphertext>(size));
    for (size_t i = 0; i < size; i++) {
        for (size_t j = 0; j < size; j++) {
            Ciphertext mult;
            evaluator.multiply_plain(encrypted_rows_A[i], encoded_cols_B[j], mult);
            evaluator.relinearize_inplace(mult, relin_keys);
            evaluator.rescale_to_next_inplace(mult);

            // Sum up the slots using rotations
            Ciphertext sum = mult;
            for (size_t k = 1; k < size; k <<= 1) {
                Ciphertext rotated;
                evaluator.rotate_vector(sum, k, gal_keys, rotated);
                evaluator.add_inplace(sum, rotated);
            }

            encrypted_result[i][j] = sum;
        }
    }

    // === Decrypt & decode the result matrix ===
    vector<vector<double>> result(size, vector<double>(size));
    for (size_t i = 0; i < size; i++) {
        for (size_t j = 0; j < size; j++) {
            Plaintext plain;
            decryptor.decrypt(encrypted_result[i][j], plain);
            vector<double> decoded;
            encoder.decode(plain, decoded);
            result[i][j] = decoded[0]; // First slot contains the sum
        }
    }

    cout << "\nDecrypted Result of A x B:\n";
    print_matrix(result);

    // === Expected Plaintext Result ===
    vector<vector<double>> expected(size, vector<double>(size, 0.0));
    for (size_t i = 0; i < size; i++)
        for (size_t j = 0; j < size; j++)
            for (size_t k = 0; k < size; k++)
                expected[i][j] += A[i][k] * B[k][j];

    cout << "Expected Plaintext Result:\n";
    print_matrix(expected);

    // === Compare with tolerance ===
    cout << "Comparison (tolerance 0.01):\n";
    for (size_t i = 0; i < size; i++) {
        for (size_t j = 0; j < size; j++) {
            double err = fabs(result[i][j] - expected[i][j]);
            cout << "[" << (err < 0.01 ? "OK" : "❌") << " error=" << err << "] ";
        }
        cout << endl;
    }
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