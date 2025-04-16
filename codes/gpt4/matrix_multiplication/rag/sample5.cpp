#include "seal/seal.h"
#include <iostream>
#include <vector>
#include <cmath>

using namespace std;
using namespace seal;

int main() {
    // Step 1: Set encryption parameters
    size_t poly_modulus_degree = 8192;
    EncryptionParameters parms(scheme_type::ckks);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 60}));

    auto context = make_shared<SEALContext>(parms);
    double scale = pow(2.0, 40);

    // Step 2: Key generation
    KeyGenerator keygen(context);
    PublicKey public_key;
    SecretKey secret_key = keygen.secret_key();
    RelinKeys relin_keys;
    GaloisKeys gal_keys;

    keygen.create_public_key(public_key);
    keygen.create_relin_keys(relin_keys);
    keygen.create_galois_keys(gal_keys);

    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    CKKSEncoder encoder(context);

    size_t slot_count = encoder.slot_count();

    // Step 3: Input matrices A and B (2x2)
    vector<double> row0_A(slot_count, 0.0);
    vector<double> row1_A(slot_count, 0.0);
    vector<double> col0_B(slot_count, 0.0);
    vector<double> col1_B(slot_count, 0.0);

    // Fill first two slots
    row0_A[0] = 1.0; row0_A[1] = 2.0;  // A row 0
    row1_A[0] = 3.0; row1_A[1] = 4.0;  // A row 1
    col0_B[0] = 5.0; col0_B[1] = 7.0;  // B col 0
    col1_B[0] = 6.0; col1_B[1] = 8.0;  // B col 1

    // Step 4: Encode and encrypt
    Plaintext p_row0, p_row1, p_col0, p_col1;
    encoder.encode(row0_A, scale, p_row0);
    encoder.encode(row1_A, scale, p_row1);
    encoder.encode(col0_B, scale, p_col0);
    encoder.encode(col1_B, scale, p_col1);

    Ciphertext c_row0, c_row1, c_col0, c_col1;
    encryptor.encrypt(p_row0, c_row0);
    encryptor.encrypt(p_row1, c_row1);
    encryptor.encrypt(p_col0, c_col0);
    encryptor.encrypt(p_col1, c_col1);

    // Step 5: Dot product helper
    auto dot_product = [&](Ciphertext &a, Ciphertext &b) {
        Ciphertext prod;
        evaluator.multiply(a, b, prod);
        evaluator.relinearize_inplace(prod, relin_keys);
        evaluator.rescale_to_next_inplace(prod);

        // Align modulus chain (optional for deeper graphs)
        Ciphertext rotated;
        Ciphertext sum = prod;
        evaluator.rotate_vector(prod, 1, gal_keys, rotated);
        evaluator.add_inplace(sum, rotated);
        return sum;
    };

    // Step 6: Compute each entry of result matrix C = A × B
    Ciphertext c00 = dot_product(c_row0, c_col0); // A[0,:] ⋅ B[:,0]
    Ciphertext c01 = dot_product(c_row0, c_col1); // A[0,:] ⋅ B[:,1]
    Ciphertext c10 = dot_product(c_row1, c_col0); // A[1,:] ⋅ B[:,0]
    Ciphertext c11 = dot_product(c_row1, c_col1); // A[1,:] ⋅ B[:,1]

    // Step 7: Decrypt and decode results
    auto decrypt_and_print = [&](Ciphertext &ct, string label) {
        Plaintext pt;
        decryptor.decrypt(ct, pt);
        vector<double> result;
        encoder.decode(pt, result);
        cout << label << ": " << result[0] << endl;
    };

    cout << "Matrix A * B (homomorphic CKKS):" << endl;
    decrypt_and_print(c00, "c00"); // Should be 1*5 + 2*7 = 19
    decrypt_and_print(c01, "c01"); // Should be 1*6 + 2*8 = 22
    decrypt_and_print(c10, "c10"); // Should be 3*5 + 4*7 = 43
    decrypt_and_print(c11, "c11"); // Should be 3*6 + 4*8 = 50

    return 0;
}
