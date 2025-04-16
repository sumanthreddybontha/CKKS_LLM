#include <iostream>
#include <vector>
#include "seal/seal.h"

using namespace std;
using namespace seal;

int main()
{
    // Step 1: Set encryption parameters for CKKS
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 60 }));

    // Step 2: Create SEALContext (modern syntax)
    SEALContext context(parms);

    // Step 3: Generate keys
    KeyGenerator keygen(context);

    PublicKey public_key;
    keygen.create_public_key(public_key);

    SecretKey secret_key = keygen.secret_key();

    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);

    // Step 4: Create encoder, encryptor, evaluator, and decryptor
    CKKSEncoder encoder(context);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    // Step 5: Encode input values
    double scale = pow(2.0, 40);
    vector<double> input1 = { 2.5 };
    vector<double> input2 = { 4.0 };

    Plaintext plain1, plain2;
    encoder.encode(input1, scale, plain1);
    encoder.encode(input2, scale, plain2);

    // Step 6: Encrypt the plaintexts
    Ciphertext encrypted1, encrypted2;
    encryptor.encrypt(plain1, encrypted1);
    encryptor.encrypt(plain2, encrypted2);

    // Step 7: Multiply encrypted values
    Ciphertext encrypted_result;
    evaluator.multiply(encrypted1, encrypted2, encrypted_result);

    // Step 8: Relinearize and rescale
    evaluator.relinearize_inplace(encrypted_result, relin_keys);
    evaluator.rescale_to_next_inplace(encrypted_result);

    // Step 9: Decrypt and decode
    Plaintext plain_result;
    decryptor.decrypt(encrypted_result, plain_result);

    vector<double> result;
    encoder.decode(plain_result, result);

    cout << "Result of CKKS multiplication: " << result[0] << endl;

    return 0;
}