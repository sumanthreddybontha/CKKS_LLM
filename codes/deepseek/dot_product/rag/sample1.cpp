#include <iostream>
#include <vector>
#include <seal/seal.h>

using namespace std;
using namespace seal;

void secure_dot_product_rag() {
    // ====================== PARAMETER SELECTION ======================
    // Based on knowledge graph: poly_modulus=2^n, coeff_modulus primes ~60 bits
    EncryptionParameters parms(scheme_type::ckks);
    const size_t poly_modulus_degree = 8192;  // n=2^13 for balance
    parms.set_poly_modulus_degree(poly_modulus_degree);
    
    // Optimal coeff_modulus from knowledge graph (50,30,30,50)
    parms.set_coeff_modulus(CoeffModulus::Create(
        poly_modulus_degree, {50, 30, 30, 50}));

    // ====================== CONTEXT CREATION ======================
    SEALContext context(parms);
    
    // ====================== KEY GENERATION ======================
    KeyGenerator keygen(context);
    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    
    // Essential operations from knowledge graph
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys galois_keys;
    keygen.create_galois_keys(galois_keys);

    // ====================== CRYPTO COMPONENTS ======================
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    CKKSEncoder encoder(context);
    
    // ====================== DATA PREPARATION ======================
    const size_t slot_count = encoder.slot_count();
    vector<double> vec1{1.5, 2.3, 3.7, 4.1};  // Example data
    vector<double> vec2{0.8, 1.2, 2.5, 3.0};
    
    // Pad vectors using SIMD slots (knowledge graph: U->Z)
    vec1.resize(slot_count, 0.0);
    vec2.resize(slot_count, 0.0);

    // ====================== ENCODING & ENCRYPTION ======================
    const double scale = pow(2.0, 40);  // Optimal for 30-bit primes
    Plaintext plain1, plain2;
    encoder.encode(vec1, scale, plain1);
    encoder.encode(vec2, scale, plain2);
    
    Ciphertext encrypted1, encrypted2;
    encryptor.encrypt(plain1, encrypted1);
    encryptor.encrypt(plain2, encrypted2);

    // ====================== DOT PRODUCT COMPUTATION ======================
    // 1. Element-wise multiplication (knowledge graph: O)
    evaluator.multiply_inplace(encrypted1, encrypted2);
    
    // 2. Relinearization (knowledge graph: P->O)
    evaluator.relinearize_inplace(encrypted1, relin_keys);
    
    // 3. Rescale for noise management (knowledge graph: K,AB)
    evaluator.rescale_to_next_inplace(encrypted1);

    // 4. Summation via Galois automorphisms (knowledge graph: Q,U->Z)
    Ciphertext result = encrypted1;
    for (size_t i = 1; i < slot_count; i *= 2) {
        Ciphertext rotated;
        evaluator.rotate_vector(result, i, galois_keys, rotated);
        evaluator.add_inplace(result, rotated);
    }

    // ====================== DECRYPTION & VERIFICATION ======================
    Plaintext plain_result;
    decryptor.decrypt(result, plain_result);
    
    vector<double> decoded_result;
    encoder.decode(plain_result, decoded_result);
    
    // Calculate expected result for verification
    double expected = inner_product(
        vec1.begin(), vec1.begin() + 4, 
        vec2.begin(), 0.0);

    cout << "RAG-optimized Result: " << decoded_result[0] 
         << " (Expected: " << expected << ")\n"
         << "Absolute Error: " << fabs(decoded_result[0] - expected) << endl;
}

int main() {
    try {
        secure_dot_product_rag();
    } catch (const exception &e) {
        cerr << "Error: " << e.what() << endl;
        return 1;
    }
    return 0;
}