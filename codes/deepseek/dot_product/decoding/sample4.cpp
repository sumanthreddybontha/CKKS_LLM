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
    cout << "  scale: " << context_data.parms().coeff_modulus().back().bit_count() << " bits" << endl;
}

int main() {
    try {
        // Step 1: CKKS setup
        EncryptionParameters parms(scheme_type::ckks);
        size_t poly_modulus_degree = 8192;
        parms.set_poly_modulus_degree(poly_modulus_degree);
        parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));
        SEALContext context(parms);
        print_parameters(context);

        // Step 2: Keys and helpers
        KeyGenerator keygen(context);
        PublicKey public_key;
        SecretKey secret_key = keygen.secret_key();
        keygen.create_public_key(public_key);
        RelinKeys relin_keys;
        keygen.create_relin_keys(relin_keys);
        Encryptor encryptor(context, public_key);
        Decryptor decryptor(context, secret_key);
        Evaluator evaluator(context);
        CKKSEncoder encoder(context);

        double scale = pow(2.0, 40);

        // Step 3: Data (10x10 matrix + 3x3 kernel)
        vector<double> matrix(100);
        for (int i = 0; i < 100; ++i) matrix[i] = i % 10;

        vector<double> kernel = {
            1.0, 0.0, -1.0,
            2.0, 0.0, -2.0,
            1.0, 0.0, -1.0
        };

        // Step 4: Encrypt full matrix
        Plaintext plain_matrix;
        encoder.encode(matrix, scale, plain_matrix);
        Ciphertext encrypted_matrix;
        encryptor.encrypt(plain_matrix, encrypted_matrix);

        // Step 5: Build kernel mask for top-left 3x3 region
        vector<double> kernel_padded(100, 0.0);
        for (int ki = 0; ki < 3; ki++) {
            for (int kj = 0; kj < 3; kj++) {
                kernel_padded[ki * 10 + kj] = kernel[ki * 3 + kj];
            }
        }

        Plaintext plain_kernel;
        encoder.encode(kernel_padded, scale, plain_kernel);

        // Match parms_id for the plaintext to ciphertext
        evaluator.mod_switch_to_inplace(plain_kernel, encrypted_matrix.parms_id());

        // Step 6: Homomorphic element-wise multiplication
        Ciphertext multiplied;
        evaluator.multiply_plain(encrypted_matrix, plain_kernel, multiplied);
        evaluator.relinearize_inplace(multiplied, relin_keys);
        evaluator.rescale_to_next_inplace(multiplied);

        // Step 7: Sum up the 9 involved values using rotate + add
        Ciphertext sum = multiplied;
        GaloisKeys gal_keys;
        keygen.create_galois_keys(gal_keys);

        for (int k = 1; k < 9; k++) {
            Ciphertext rotated;
            evaluator.rotate_vector(sum, k, gal_keys, rotated);
            evaluator.add_inplace(sum, rotated);
        }

        // Step 8: Decrypt and decode result
        Plaintext plain_result;
        decryptor.decrypt(sum, plain_result);
        vector<double> result;
        encoder.decode(plain_result, result);

        cout << "Dot product at (0,0): " << result[0] << endl;
        
        return 0;
    } catch (const exception &e) {
        cerr << "Error: " << e.what() << endl;
        return 1;
    }
}