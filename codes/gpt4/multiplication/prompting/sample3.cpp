#include "seal/seal.h"
#include <iostream>
#include <vector>

using namespace std;
using namespace seal;

int main()
{
    // Step 1: Set encryption parameters for CKKS
    EncryptionParameters parms(scheme_type::ckks);

    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));

    // Create SEALContext (new syntax)
    SEALContext context(parms);
    // print_parameters(context);
    cout << endl;

    // Step 2: Create keys and helper classes
    KeyGenerator keygen(context);

    PublicKey public_key;
    keygen.create_public_key(public_key);

    SecretKey secret_key = keygen.secret_key();

    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    CKKSEncoder encoder(context);
    Evaluator evaluator(context);

    // Step 3: Encode two numbers
    double num1 = 3.2, num2 = 1.5;
    double scale = pow(2.0, 40);

    Plaintext plain1, plain2;
    encoder.encode(num1, scale, plain1);
    encoder.encode(num2, scale, plain2);

    // Step 4: Encrypt the plaintexts
    Ciphertext encrypted1, encrypted2;
    encryptor.encrypt(plain1, encrypted1);
    encryptor.encrypt(plain2, encrypted2);

    // Step 5: Multiply the ciphertexts
    Ciphertext encrypted_result;
    evaluator.multiply(encrypted1, encrypted2, encrypted_result);

    // Step 6: Relinearize the result
    evaluator.relinearize_inplace(encrypted_result, relin_keys);

    // Step 7: Rescale to manage scale growth
    evaluator.rescale_to_next_inplace(encrypted_result);

    // Step 8: Decrypt and decode the result
    Plaintext plain_result;
    decryptor.decrypt(encrypted_result, plain_result);

    vector<double> result;
    encoder.decode(plain_result, result);

    cout << "Decrypted result: " << result[0] << endl;

    return 0;
}