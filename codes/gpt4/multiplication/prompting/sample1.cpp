#include "seal/seal.h"
#include <iostream>
#include <vector>

int main()
{
    using namespace std;
    using namespace seal;

    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));

    SEALContext context(parms);

    KeyGenerator keygen(context);
    PublicKey public_key;
    keygen.create_public_key(public_key);

    SecretKey secret_key = keygen.secret_key();
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);

    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    CKKSEncoder encoder(context);

    double scale = pow(2.0, 40);

    vector<double> input1 = { 1.1, 2.2, 3.3 };
    vector<double> input2 = { 4.4, 5.5, 6.6 };

    Plaintext plain1, plain2;
    encoder.encode(input1, scale, plain1);
    encoder.encode(input2, scale, plain2);

    Ciphertext encrypted1, encrypted2;
    encryptor.encrypt(plain1, encrypted1);
    encryptor.encrypt(plain2, encrypted2);

    Ciphertext encrypted_result;
    evaluator.multiply(encrypted1, encrypted2, encrypted_result);
    evaluator.relinearize_inplace(encrypted_result, relin_keys);
    evaluator.rescale_to_next_inplace(encrypted_result);

    Plaintext plain_result;
    decryptor.decrypt(encrypted_result, plain_result);

    vector<double> result;
    encoder.decode(plain_result, result);

    cout << "Result after multiplication: ";
    for (double val : result)
    {
        cout << val << " ";
    }
    cout << endl;

    return 0;
}