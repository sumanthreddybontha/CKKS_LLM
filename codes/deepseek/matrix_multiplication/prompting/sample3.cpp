#include <iostream>
#include <vector>
#include <cmath>
#include "seal/seal.h"

using namespace std;
using namespace seal;

// Helper to print encryption parameters
void print_parameters(const SEALContext &context)
{
    auto context_data = context.key_context_data();
    cout << "Encryption parameters:" << endl;
    cout << "Scheme: CKKS" << endl;
    cout << "Poly modulus degree: " << context_data->parms().poly_modulus_degree() << endl;
    cout << "Coeff modulus size: " << context_data->total_coeff_modulus_bit_count() << " bits" << endl;
    cout << endl;
}

// Helper to print modulus chain index and scale
void print_chain_index(shared_ptr<SEALContext> context, const Ciphertext &ct, const string &label)
{
    auto context_data = context->get_context_data(ct.parms_id());
    size_t chain_index = context_data->chain_index();
    cout << label << " at chain index: " << chain_index
         << ", scale: 2^" << log2(ct.scale()) << endl;
}

int main()
{
    // Step 1: Set encryption parameters
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 60}));

    auto context = make_shared<SEALContext>(parms, true, sec_level_type::tc128);
    print_parameters(*context);

    // Step 2: Keys and setup
    KeyGenerator keygen(*context);
    PublicKey public_key;
    keygen.create_public_key(public_key);
    SecretKey secret_key = keygen.secret_key();

    Encryptor encryptor(*context, public_key);
    Evaluator evaluator(*context);
    Decryptor decryptor(*context, secret_key);
    CKKSEncoder encoder(*context);

    double scale = pow(2.0, 40);

    // Step 3: Define 2x2 matrices A and B
    vector<double> A = {1.0, 2.0, 3.0, 4.0}; // Row-major: A = [[1, 2], [3, 4]]
    vector<double> B = {5.0, 6.0, 7.0, 8.0}; // B = [[5, 6], [7, 8]]

    // Step 4: Encode and encrypt A and B
    Plaintext plain_A, plain_B;
    encoder.encode(A, scale, plain_A);
    encoder.encode(B, scale, plain_B);

    Ciphertext enc_A, enc_B;
    encryptor.encrypt(plain_A, enc_A);
    encryptor.encrypt(plain_B, enc_B);

    print_chain_index(context, enc_A, "Encrypted A");
    print_chain_index(context, enc_B, "Encrypted B");

    // Step 5: Encode masks for manual matrix multiplication
    Plaintext mask_a11b11, mask_a12b21;
    encoder.encode(vector<double>{5.0, 0.0, 0.0, 0.0}, scale, mask_a11b11); // A11*B11
    encoder.encode(vector<double>{0.0, 6.0, 0.0, 0.0}, scale, mask_a12b21); // A12*B21

    // Step 6: Multiply and rescale
    Ciphertext a11b11, a12b21;
    evaluator.multiply_plain(enc_A, mask_a11b11, a11b11);
    evaluator.rescale_to_next_inplace(a11b11);
    print_chain_index(context, a11b11, "A11 * B11");

    evaluator.multiply_plain(enc_A, mask_a12b21, a12b21);
    evaluator.rescale_to_next_inplace(a12b21);
    print_chain_index(context, a12b21, "A12 * B21");

    // Step 7: Modulus switching and scale alignment
    parms_id_type common_parms_id = a11b11.parms_id();
    evaluator.mod_switch_to_inplace(a12b21, common_parms_id);
    a11b11.scale() = scale;
    a12b21.scale() = scale;

    // Step 8: Add the partial results
    Ciphertext c11;
    evaluator.add(a11b11, a12b21, c11);
    print_chain_index(context, c11, "C11 (final)");

    // Step 9: Decrypt and decode result
    Plaintext plain_result;
    vector<double> result;
    decryptor.decrypt(c11, plain_result);
    encoder.decode(plain_result, result);

    cout << "\nDecrypted C11 result (approx): " << result[0] << endl;
    cout << "(Expected: 1*5 + 2*7 = 19)" << endl;

    return 0;
}
