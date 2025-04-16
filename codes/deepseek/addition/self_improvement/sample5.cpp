#include <seal/seal.h>
#include <vector>
#include <iostream>
#include <sys/resource.h>
using namespace seal;
using namespace std;

void print_memory_usage() {
    rusage usage;
    getrusage(RUSAGE_SELF, &usage);
    cout << "Memory usage: " << usage.ru_maxrss/1024 << " MB" << endl;
}

int main() {
    // Lean parameter setup
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {40, 30, 40}));
    
    SEALContext context(parms);
    KeyGenerator keygen(context);
    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    
    // Core operations
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    CKKSEncoder encoder(context);
    Decryptor decryptor(context, secret_key);
    
    // Chunked processing
    constexpr size_t total = 10000, chunk_size = 512;
    
    for (size_t chunk = 0; chunk < total/chunk_size; chunk++) {
        print_memory_usage();
        
        // Process chunk
        vector<double> input1(chunk_size), input2(chunk_size);
        for (size_t i = 0; i < chunk_size; i++) {
            input1[i] = (chunk*chunk_size + i) * 1.1;
            input2[i] = (chunk*chunk_size + i) * 2.2;
        }
        
        Plaintext plain1, plain2;
        encoder.encode(input1, pow(2.0, 30), plain1);
        encoder.encode(input2, pow(2.0, 30), plain2);
        
        Ciphertext encrypted1, encrypted2;
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        
        evaluator.add_inplace(encrypted1, encrypted2);
        
        // Verify first chunk
        if (chunk == 0) {
            Plaintext plain_result;
            decryptor.decrypt(encrypted1, plain_result);
            
            vector<double> result;
            encoder.decode(plain_result, result);
            
            cout << "First element result: " << result[0] << endl;
        }
    }
    
    print_memory_usage();
    return 0;
}