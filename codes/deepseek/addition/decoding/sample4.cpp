#include <iostream>
#include <vector>
#include <seal/seal.h>
#include <omp.h>

using namespace std;
using namespace seal;

int main() {
    // Setup
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {50, 30, 30, 50}));
    
    double scale = pow(2.0, 40);
    SEALContext context(parms);
    
    // Key generation
    KeyGenerator keygen(context);
    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    
    // Prepare large vectors
    const size_t vec_size = 10000;
    vector<double> input1(vec_size), input2(vec_size);
    
    #pragma omp parallel for
    for (size_t i = 0; i < vec_size; i++) {
        input1[i] = i * 1.1;
        input2[i] = i * 2.2;
    }
    
    // Parallel encoding
    vector<Plaintext> plains1(omp_get_max_threads());
    vector<Plaintext> plains2(omp_get_max_threads());
    
    #pragma omp parallel
    {
        int tid = omp_get_thread_num();
        CKKSEncoder encoder(context);
        encoder.encode(vector<double>(input1.begin()+tid*vec_size/omp_get_max_threads(), 
                                   input1.begin()+(tid+1)*vec_size/omp_get_max_threads()), 
                      scale, plains1[tid]);
        encoder.encode(vector<double>(input2.begin()+tid*vec_size/omp_get_max_threads(), 
                                   input2.begin()+(tid+1)*vec_size/omp_get_max_threads()), 
                      scale, plains2[tid]);
    }
    
    cout << "Parallel processing complete" << endl;
    return 0;
}