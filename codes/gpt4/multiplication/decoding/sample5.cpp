#include <iostream>
#include <vector>
#include <seal/seal.h>

using namespace std;
using namespace seal;

int main()
{
    // Step 1: Set encryption parameters
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));

    // Step 2: Create context
    SEALContext context(parms);
    // print_parameters(context);
    cout << "Parameter validation: " << (context.key_context_data()->qualifiers().using_fft ? "Passed" : "Failed") << endl;

    // Step 3: Create keys
    KeyGenerator keygen(context);
    PublicKey public_key;
    keygen.create_public_key(public_key);
    SecretKey secret_key = keygen.secret_key();
    RelinKeys relin_keys;
keygen.create_relin_keys(relin_keys);

    // Step 4: Create helpers
    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    CKKSEncoder encoder(context);

    // Step 5: Prepare data
    constexpr size_t MATRIX_SIZE = 10;
    constexpr size_t KERNEL_SIZE = 3;
    vector<double> input_matrix(MATRIX_SIZE * MATRIX_SIZE);
    vector<double> kernel(MATRIX_SIZE * MATRIX_SIZE, 0.0); // zero-padded to match matrix size

    // Fill input matrix with values 1 to 100
    for (size_t i = 0; i < input_matrix.size(); i++) {
        input_matrix[i] = static_cast<double>(i + 1);
    }

    // Fill 3x3 kernel in top-left corner, rest are zeros
    double avg_value = 1.0 / 9.0;
    for (size_t i = 0; i < KERNEL_SIZE; ++i) {
        for (size_t j = 0; j < KERNEL_SIZE; ++j) {
            kernel[i * MATRIX_SIZE + j] = avg_value;
        }
    }

    // Step 6: Encode and Encrypt
    double scale = pow(2.0, 40);
    Plaintext plain_matrix, plain_kernel;
    encoder.encode(input_matrix, scale, plain_matrix);
    encoder.encode(kernel, scale, plain_kernel);

    Ciphertext encrypted_matrix, encrypted_kernel;
    encryptor.encrypt(plain_matrix, encrypted_matrix);
    encryptor.encrypt(plain_kernel, encrypted_kernel);

    // Step 7: Multiply encrypted matrix and kernel
    Ciphertext encrypted_result;
    evaluator.multiply(encrypted_matrix, encrypted_kernel, encrypted_result);
    evaluator.relinearize_inplace(encrypted_result, relin_keys);
    evaluator.rescale_to_next_inplace(encrypted_result);

    // Step 8: Decrypt and decode the result
    Plaintext plain_result;
    decryptor.decrypt(encrypted_result, plain_result);

    vector<double> result;
    encoder.decode(plain_result, result);

    // Step 9: Print some output
    cout << "\nEncrypted element-wise multiplication result (first 10 elements):" << endl;
    for (size_t i = 0; i < 10; ++i) {
        cout << result[i] << " ";
    }
    cout << endl;

    return 0;
}