#include <iostream>
#include <vector>
#include <seal/seal.h>

using namespace std;
using namespace seal;

int main() {
    // Party A: Setup and key generation
    EncryptionParameters parms(scheme_type::ckks);
    parms.set_poly_modulus_degree(8192);
    parms.set_coeff_modulus(CoeffModulus::Create(8192, {50, 30, 30, 50}));

    SEALContext context(parms);
    KeyGenerator keygen(context);
    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys galois_keys;
    keygen.create_galois_keys(galois_keys);

    // Party A: Encrypt vector
    vector<double> vec_a{1.0, 2.0, 3.0, 4.0};
    CKKSEncoder encoder(context);
    size_t slot_count = encoder.slot_count();
    vec_a.resize(slot_count, 0.0);

    double scale = pow(2.0, 40);
    Plaintext plain_a;
    encoder.encode(vec_a, scale, plain_a);
    Ciphertext encrypted_a;
    Encryptor encryptor(context, public_key);
    encryptor.encrypt(plain_a, encrypted_a);

    // Party B: Receives public key and encrypted vector
    // Party B has vector {2.0, 3.0, 4.0, 5.0}
    vector<double> vec_b{2.0, 3.0, 4.0, 5.0};
    vec_b.resize(slot_count, 0.0);

    // Party B computes
    Evaluator evaluator(context);
    Plaintext plain_b;
    encoder.encode(vec_b, scale, plain_b);
    Ciphertext encrypted_b;
    encryptor.encrypt(plain_b, encrypted_b);

    evaluator.multiply_inplace(encrypted_a, encrypted_b);
    evaluator.relinearize_inplace(encrypted_a, relin_keys);
    evaluator.rescale_to_next_inplace(encrypted_a);

    // Sum elements
    Ciphertext result = encrypted_a;
    for (size_t i = 1; i < slot_count; i *= 2) {
        Ciphertext rotated;
        evaluator.rotate_vector(result, i, galois_keys, rotated);
        evaluator.add_inplace(result, rotated);
    }

    // Party A decrypts
    Decryptor decryptor(context, secret_key);
    Plaintext plain_result;
    decryptor.decrypt(result, plain_result);
    vector<double> decoded;
    encoder.decode(plain_result, decoded);

    cout << "Secure dot product result: " << decoded[0] << endl;
    return 0;
}