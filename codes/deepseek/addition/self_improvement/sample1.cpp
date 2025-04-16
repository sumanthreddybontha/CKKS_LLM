// Addition with inline comments and vector input
#include "seal/seal.h"
#include <iostream>
#include <algorithm> // for std::min

using namespace std;
using namespace seal;

int main() {
    // Setup CKKS encryption parameters
    EncryptionParameters parms(scheme_type::ckks);
    parms.set_poly_modulus_degree(8192);
    parms.set_coeff_modulus(CoeffModulus::Create(8192, { 60, 40, 40, 60 }));

    SEALContext context(parms);
    KeyGenerator keygen(context);
    PublicKey pk;
    keygen.create_public_key(pk);
    SecretKey sk = keygen.secret_key();

    Encryptor encryptor(context, pk);
    Decryptor decryptor(context, sk);
    CKKSEncoder encoder(context);
    Evaluator evaluator(context);

    double scale = pow(2.0, 40);

    // Sample vector inputs
    vector<double> vec1 = {10.0, 20.0};
    vector<double> vec2 = {30.0, 40.0};

    // Encode
    Plaintext pt1, pt2;
    encoder.encode(vec1, scale, pt1);
    encoder.encode(vec2, scale, pt2);

    // Encrypt
    Ciphertext ct1, ct2;
    encryptor.encrypt(pt1, ct1);
    encryptor.encrypt(pt2, ct2);

    // Homomorphic addition
    Ciphertext ct_sum;
    evaluator.add(ct1, ct2, ct_sum);

    // Decrypt
    Plaintext pt_sum;
    decryptor.decrypt(ct_sum, pt_sum);
    vector<double> result;
    encoder.decode(pt_sum, result);

    // Truncated output
    cout << "Decrypted sum: ";
    size_t print_count = min(result.size(), size_t(5));
    for (size_t i = 0; i < print_count; ++i) {
        cout << result[i] << " ";
    }
    if (result.size() > 5) {
        cout << "... (truncated)";
    }
    cout << endl;

    return 0;
}
