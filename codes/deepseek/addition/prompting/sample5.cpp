#include <seal/seal.h>
#include <vector>
#include <sys/resource.h>
#include <iostream>  // Added for std::cout

using namespace seal;  // This allows using SEAL classes without namespace

void print_memory() {
    rusage usage;
    getrusage(RUSAGE_SELF, &usage);
    std::cout << "Memory: " << usage.ru_maxrss/1024 << "MB" << std::endl;
}

int main() {
    EncryptionParameters parms(scheme_type::ckks);
    parms.set_poly_modulus_degree(8192);
    parms.set_coeff_modulus(CoeffModulus::Create(8192, {50, 30, 50}));
    
    SEALContext context(parms);
    KeyGenerator keygen(context);
    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    CKKSEncoder encoder(context);
    
    constexpr size_t total = 10000, chunk_size = 512;
    for (size_t chunk = 0; chunk < total/chunk_size; chunk++) {
        print_memory();
        std::vector<double> input1(chunk_size), input2(chunk_size);
        for (size_t i = 0; i < chunk_size; i++) {
            input1[i] = (chunk*chunk_size + i) * 1.1;
            input2[i] = (chunk*chunk_size + i) * 2.2;
        }
        
        seal::Plaintext plain1, plain2;  // Can also use just Plaintext if 'using namespace seal'
        encoder.encode(input1, pow(2.0, 40), plain1);
        encoder.encode(input2, pow(2.0, 40), plain2);
        
        seal::Ciphertext encrypted1, encrypted2;  // Can also use just Ciphertext
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        
        evaluator.add_inplace(encrypted1, encrypted2);
    }
    
    return 0;
}