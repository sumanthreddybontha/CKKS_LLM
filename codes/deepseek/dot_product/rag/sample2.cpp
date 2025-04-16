#include <iostream>
#include <vector>
#include <seal/seal.h>
#include <omp.h>

using namespace std;
using namespace seal;

void parallel_dot_product() {
    EncryptionParameters parms(scheme_type::ckks);
    const size_t poly_modulus_degree = 16384;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 60}));

    SEALContext context(parms);
    KeyGenerator keygen(context);
    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys galois_keys;
    keygen.create_galois_keys(galois_keys);

    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    CKKSEncoder encoder(context);
    const size_t slot_count = encoder.slot_count();

    // Generate large random vectors
    vector<double> vec1(slot_count), vec2(slot_count);
    #pragma omp parallel for
    for (size_t i = 0; i < slot_count; i++) {
        vec1[i] = static_cast<double>(rand()) / RAND_MAX;
        vec2[i] = static_cast<double>(rand()) / RAND_MAX;
    }

    // Parallel encoding
    double scale = pow(2.0, 50);
    Plaintext plain1, plain2;
    #pragma omp parallel sections
    {
        #pragma omp section
        encoder.encode(vec1, scale, plain1);
        #pragma omp section
        encoder.encode(vec2, scale, plain2);
    }

    Ciphertext encrypted1, encrypted2;
    encryptor.encrypt(plain1, encrypted1);
    encryptor.encrypt(plain2, encrypted2);

    // Parallelized computation
    Ciphertext result;
    evaluator.multiply(encrypted1, encrypted2, result);
    evaluator.relinearize_inplace(result, relin_keys);
    evaluator.rescale_to_next_inplace(result);

    #pragma omp parallel for
    for (size_t i = 1; i < slot_count; i *= 2) {
        Ciphertext rotated;
        evaluator.rotate_vector(result, i, galois_keys, rotated);
        evaluator.add_inplace(result, rotated);
    }

    Plaintext plain_result;
    decryptor.decrypt(result, plain_result);
    vector<double> decoded;
    encoder.decode(plain_result, decoded);

    cout << "Parallel result: " << decoded[0] << endl;
}