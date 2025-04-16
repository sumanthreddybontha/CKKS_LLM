#include <seal/seal.h>
#include <iostream>
#include <vector>
#include <cmath>

using namespace std;
using namespace seal;

int main() {
    // Step 1: Set CKKS parameters
    size_t poly_modulus_degree = 8192;
    EncryptionParameters parms(scheme_type::ckks);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 60}));

    // Step 2: Create SEAL context
    SEALContext context(parms);

    // Step 3: Key generation
    KeyGenerator keygen(context);

    PublicKey public_key;
    keygen.create_public_key(public_key);

    SecretKey secret_key = keygen.secret_key();

    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);

    GaloisKeys gal_keys;
    keygen.create_galois_keys(gal_keys);

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    CKKSEncoder encoder(context);

    // Step 4: Input vectors
    vector<double> vec1 = {1.1, 2.2, 3.3, 4.4};
    vector<double> vec2 = {5.0, 6.0, 7.0, 8.0};
    double scale = pow(2.0, 40);

    // Step 5: Encode and encrypt
    Plaintext pt1, pt2;
    encoder.encode(vec1, scale, pt1);
    encoder.encode(vec2, scale, pt2);

    Ciphertext ct1, ct2;
    encryptor.encrypt(pt1, ct1);
    encryptor.encrypt(pt2, ct2);

    // Step 6: Element-wise multiplication
    Ciphertext prod;
    evaluator.multiply(ct1, ct2, prod);
    evaluator.relinearize_inplace(prod, relin_keys);
    evaluator.rescale_to_next_inplace(prod);

    // Step 7: Sum all elements (dot product using rotations)
    // Ensure modulus and scale are aligned for rotation
    Ciphertext dot = prod;
    size_t n = vec1.size();

    for (size_t i = 1; i < n; i <<= 1) {
        Ciphertext rotated;
        evaluator.rotate_vector(dot, i, gal_keys, rotated);
        evaluator.add_inplace(dot, rotated);
    }

    // Step 8: Decrypt and decode
    Plaintext result_plain;
    decryptor.decrypt(dot, result_plain);

    vector<double> result;
    encoder.decode(result_plain, result);

    cout << "Encrypted dot product (approximate): " << result[0] << endl;

    return 0;
}
