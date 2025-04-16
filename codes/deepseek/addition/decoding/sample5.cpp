#include <iostream>
#include <vector>
#include <seal/seal.h>
#include <sys/resource.h>

using namespace std;
using namespace seal;

void print_memory_usage() {
    struct rusage usage;
    getrusage(RUSAGE_SELF, &usage);
    cout << "Memory used: " << usage.ru_maxrss / 1024 << " MB" << endl;
}

int main() {
    print_memory_usage();
    
    // Lean parameter setup
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {50, 30, 50}));
    
    double scale = pow(2.0, 40);
    SEALContext context(parms);
    print_memory_usage();
    
    // Reusable objects
    KeyGenerator keygen(context);
    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    
    // Single encryptor/decryptor
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    CKKSEncoder encoder(context);
    print_memory_usage();
    
    // Process in chunks
    const size_t total_size = 1000;
    const size_t chunk_size = 100;
    
    for (size_t chunk = 0; chunk < total_size/chunk_size; chunk++) {
        vector<double> input1(chunk_size), input2(chunk_size);
        for (size_t i = 0; i < chunk_size; i++) {
            input1[i] = (chunk*chunk_size + i) * 1.1;
            input2[i] = (chunk*chunk_size + i) * 2.2;
        }
        
        Plaintext plain1, plain2;
        encoder.encode(input1, scale, plain1);
        encoder.encode(input2, scale, plain2);
        
        Ciphertext encrypted1, encrypted2;
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        
        evaluator.add_inplace(encrypted1, encrypted2);
        
        Plaintext plain_result;
        decryptor.decrypt(encrypted1, plain_result);
        vector<double> result;
        encoder.decode(plain_result, result);
        
        cout << "Processed chunk " << chunk << endl;
        print_memory_usage();
    }
    
    return 0;
}