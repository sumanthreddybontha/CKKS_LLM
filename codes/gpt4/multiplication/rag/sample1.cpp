#include "seal/seal.h"
#include <iostream>
#include <vector>
#include <cmath>

using namespace std;
using namespace seal;

int main() {
    // Step 1: Set up CKKS encryption parameters (poly_modulus, coeff_modulus)
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 60}));
    SEALContext context(parms);

    // Step 2: Key generation (public/secret key, relinearization keys)
    KeyGenerator keygen(context);
    PublicKey public_key; keygen.create_public_key(public_key);
    SecretKey secret_key = keygen.secret_key();
    RelinKeys relin_keys; keygen.create_relin_keys(relin_keys);

    // Step 3: Encoder and Encryptor/Decryptor
    CKKSEncoder encoder(context);
    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    double scale = pow(2.0, 40);

    // Step 4: Define two input vectors for multiplication
    vector<double> vec1 = {1.1, 2.2, 3.3, 4.4};
    vector<double> vec2 = {0.5, 1.0, 1.5, 2.0};

    // Step 5: Encode and encrypt the input vectors
    Plaintext pt1, pt2;
    encoder.encode(vec1, scale, pt1);
    encoder.encode(vec2, scale, pt2);

    Ciphertext ct1, ct2;
    encryptor.encrypt(pt1, ct1);
    encryptor.encrypt(pt2, ct2);

    // Step 6: Perform encrypted multiplication (Multiply -> Relinearize -> Rescale)
    Ciphertext ct_result;
    evaluator.multiply(ct1, ct2, ct_result);
    evaluator.relinearize_inplace(ct_result, relin_keys);
    evaluator.rescale_to_next_inplace(ct_result);

    // Step 7: Decrypt and decode the result
    Plaintext pt_result;
    decryptor.decrypt(ct_result, pt_result);

    vector<double> result;
    encoder.decode(pt_result, result);

    // Step 8: Output the result
    cout << "Encrypted element-wise multiplication result (approximate):\n";
    for (double val : result) {
        cout << val << " ";
    }
    cout << endl;

    return 0;
}
