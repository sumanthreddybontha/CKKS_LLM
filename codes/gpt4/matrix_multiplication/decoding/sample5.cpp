#include "seal/seal.h"
#include <iostream>
#include <vector>
#include <cmath>

using namespace std;
using namespace seal;

// Helper to print encryption parameters
void print_parameters(const SEALContext &context) {
    auto &context_data = *context.key_context_data();
    cout << "Encryption parameters:" << endl;
    cout << "  Poly modulus degree: " << context_data.parms().poly_modulus_degree() << endl;
    cout << "  Coeff moduli bit sizes: ";
    for (const auto &mod : context_data.parms().coeff_modulus()) {
        cout << mod.bit_count() << " ";
    }
    cout << endl;
}

int main() {
    // Step 1: Set up encryption parameters
    size_t poly_modulus_degree = 8192;
    EncryptionParameters parms(scheme_type::ckks);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 60}));

    // Create SEALContext
    SEALContext context(parms);

    // Print the parameters
    print_parameters(context);
    cout << endl;

    // Step 2: Generate Keys
    KeyGenerator keygen(context);

    PublicKey public_key;
    keygen.create_public_key(public_key); // ✅ fixed

    SecretKey secret_key = keygen.secret_key();

    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys); // ✅ fixed

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    CKKSEncoder encoder(context);

    double scale = pow(2.0, 40);

    // Step 3: Define and encrypt input matrices
    vector<double> mat1 = {1.0, 2.0, 3.0, 4.0}; // A
    vector<double> mat2 = {5.0, 6.0, 7.0, 8.0}; // B

    vector<Ciphertext> encrypted_mat1(4);
    vector<Ciphertext> encrypted_mat2(4);

    for (size_t i = 0; i < 4; i++) {
        Plaintext plain;
        encoder.encode(mat1[i], scale, plain);
        encryptor.encrypt(plain, encrypted_mat1[i]);

        encoder.encode(mat2[i], scale, plain);
        encryptor.encrypt(plain, encrypted_mat2[i]);
    }

    // Step 4: Matrix Multiplication
    vector<Ciphertext> result(4);
    Ciphertext temp;

    evaluator.multiply(encrypted_mat1[0], encrypted_mat2[0], result[0]);
    evaluator.relinearize_inplace(result[0], relin_keys);
    evaluator.rescale_to_next_inplace(result[0]);

    evaluator.multiply(encrypted_mat1[1], encrypted_mat2[2], temp);
    evaluator.relinearize_inplace(temp, relin_keys);
    evaluator.rescale_to_next_inplace(temp);
    evaluator.add_inplace(result[0], temp);

    evaluator.multiply(encrypted_mat1[0], encrypted_mat2[1], result[1]);
    evaluator.relinearize_inplace(result[1], relin_keys);
    evaluator.rescale_to_next_inplace(result[1]);

    evaluator.multiply(encrypted_mat1[1], encrypted_mat2[3], temp);
    evaluator.relinearize_inplace(temp, relin_keys);
    evaluator.rescale_to_next_inplace(temp);
    evaluator.add_inplace(result[1], temp);

    evaluator.multiply(encrypted_mat1[2], encrypted_mat2[0], result[2]);
    evaluator.relinearize_inplace(result[2], relin_keys);
    evaluator.rescale_to_next_inplace(result[2]);

    evaluator.multiply(encrypted_mat1[3], encrypted_mat2[2], temp);
    evaluator.relinearize_inplace(temp, relin_keys);
    evaluator.rescale_to_next_inplace(temp);
    evaluator.add_inplace(result[2], temp);

    evaluator.multiply(encrypted_mat1[2], encrypted_mat2[1], result[3]);
    evaluator.relinearize_inplace(result[3], relin_keys);
    evaluator.rescale_to_next_inplace(result[3]);

    evaluator.multiply(encrypted_mat1[3], encrypted_mat2[3], temp);
    evaluator.relinearize_inplace(temp, relin_keys);
    evaluator.rescale_to_next_inplace(temp);
    evaluator.add_inplace(result[3], temp);

    // Step 5: Decrypt and decode
    cout << "\nDecrypted result matrix C:" << endl;
    for (size_t i = 0; i < 4; i++) {
        Plaintext plain_result;
        decryptor.decrypt(result[i], plain_result);
        vector<double> decoded;
        encoder.decode(plain_result, decoded);
        cout << decoded[0] << " ";
        if (i % 2 == 1) cout << endl;
    }

    return 0;
}
