#include <seal/seal.h>
#include <vector>
#include <cmath>
#include <numeric>
#include <iostream>
#include <stdexcept>

using namespace seal;
using namespace std;

double safe_dot_product(const vector<double>& vec1, const vector<double>& vec2) {
    // 1. Validate input
    if (vec1.size() != vec2.size()) {
        throw invalid_argument("Vectors must be of equal length");
    }

    // 2. Parameter setup with safe bounds
    EncryptionParameters parms(scheme_type::ckks);
    const size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    
    // Recommended modulus chain for 128-bit security
    vector<int> moduli_bits = {50, 30, 50};  // Total 130 bits
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, moduli_bits));
    
    // 3. Context validation
    SEALContext context(parms);
    if (!context.parameters_set()) {
        throw runtime_error("Invalid SEAL parameters");
    }

    // 4. Calculate safe scale factor (middle of max bit size)
    const double scale = pow(2.0, 30);  // 40 bits is safe for this modulus chain
    if (log2(scale) > moduli_bits[0]) {
        throw runtime_error("Scale too large for selected parameters");
    }

    // 5. Initialize SEAL components
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    
    CKKSEncoder encoder(context);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    // 6. Validate vector size
    const size_t slot_count = encoder.slot_count();
    if (vec1.size() > slot_count) {
        throw invalid_argument("Vector size exceeds slot capacity");
    }

    // 7. Encoding with padding
    vector<double> padded_vec1(slot_count, 0.0);
    vector<double> padded_vec2(slot_count, 0.0);
    copy(vec1.begin(), vec1.end(), padded_vec1.begin());
    copy(vec2.begin(), vec2.end(), padded_vec2.begin());

    Plaintext plain1, plain2;
    encoder.encode(padded_vec1, scale, plain1);
    encoder.encode(padded_vec2, scale, plain2);
    
    // 8. Encryption
    Ciphertext encrypted1, encrypted2;
    encryptor.encrypt(plain1, encrypted1);
    encryptor.encrypt(plain2, encrypted2);
    
    // 9. Computation with proper rescaling
    Ciphertext encrypted_product;
    evaluator.multiply(encrypted1, encrypted2, encrypted_product);
    evaluator.relinearize_inplace(encrypted_product, relin_keys);
    evaluator.rescale_to_next_inplace(encrypted_product);
    
    // 10. Decryption
    Plaintext plain_result;
    decryptor.decrypt(encrypted_product, plain_result);
    
    // 11. Decoding and result calculation
    vector<double> result;
    encoder.decode(plain_result, result);
    
    return accumulate(result.begin(), result.begin() + vec1.size(), 0.0);
}

int main() {
    vector<double> vec1 = {1.0, 2.0, 3.0, 4.0};
    vector<double> vec2 = {0.5, 1.5, 2.5, 3.5};

    try {
        double result = safe_dot_product(vec1, vec2);
        cout << "Dot product result: " << result << endl;
        cout << "Expected result: " << inner_product(vec1.begin(), vec1.end(), vec2.begin(), 0.0) << endl;
    } catch (const exception& e) {
        cerr << "Error: " << e.what() << endl;
        return 1;
    }

    return 0;
}