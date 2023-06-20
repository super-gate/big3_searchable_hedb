#include <iostream>

#include "HDB_supergate.hpp"

using namespace helib;
using namespace std;

namespace HDB_supergate_ {
    struct BGV_param MakeBGVParam(long p, 
                                  long d, 
                                  long m, 
                                  long nb_primes, 
                                  long c, 
                                  long expansion_len, 
                                  long scale, 
                                  long r) 
    {
        return BGV_param {p, d, m, nb_primes, c, expansion_len, scale, r};
    }

    Context MakeBGVContext(long p, 
                           long m, 
                           long nb_primes, 
                           long c, 
                           long scale, 
                           long r)
    { 
        return ContextBuilder<BGV>()
                    .m(m)
                    .p(p)
                    .r(r)
                    .bits(nb_primes)
                    .c(c) 
                    .scale(scale)
                    .build();
                        
    }    

    Context MakeBGVContext(struct BGV_param params) 
    {        
        return ContextBuilder<BGV>()
                    .m(params.m)
                    .p(params.p)
                    .r(params.r)
                    .bits(params.nb_primes)
                    .c(params.c) 
                    .scale(params.scale)
                    .build();
    }

    istream& operator>>(istream& str, CSVRow& data)
    {
        data.readNextRow(str);
        return str;
    }

    long findNSlots(long p, long m) {
        long phiM = phi_N(m);
        long mulOrd = multOrd(p, m);

        return phiM / mulOrd;
    }
};

