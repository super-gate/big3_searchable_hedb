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

    void PtxtIndex::insert(long k, unsigned long v)
    {
        auto it = std::find(keys.begin(), keys.end(), k);
        if (it == keys.end())
        {
            std::vector<unsigned long> new_vec{};
            new_vec.push_back(v);
            plaintext_index.emplace_back(std::pair(k, new_vec));
            keys.push_back(k);
            if (!c) c = 1;
        }
        else 
        {
            plaintext_index[int(it - keys.begin())].second.emplace_back(v);
            int size = plaintext_index[int(it - keys.begin())].second.size();
            if (size > c) c = size;
        }
    }

    void PtxtIndex::printIndex()
    {
        for (auto& pair :plaintext_index)
        {
            std::cout << pair.first << ": [";
            for (auto& val: pair.second)
                std::cout << val << ", ";
            std::cout << "]\n" << std::endl;
        }
    }

    void PtxtIndexFile::insert(std::string col, long k, unsigned long v)
    {
        auto it = std::find(cols.begin(), cols.end(), col);
        if (it == cols.end())
        {
            PtxtIndex new_index{};
            new_index.insert(k, v);
            IndexFile.emplace_back(col, new_index);
            cols.emplace_back(col);
        }
        else IndexFile[int(it - cols.begin())].second.insert(k, v);
    }

    void PtxtIndexFile::printIndex(std::string col)
    {
        auto it = std::find(cols.begin(), cols.end(), col);
        if (it == cols.end())
        {
            std::cout << "Cannot find index for the column..." << std::endl;
        }
        else IndexFile[int(it - cols.begin())].second.printIndex();
    }

    void PtxtIndexFile::printIndexFile()
    {
        for (auto& ind: IndexFile)
        {
            std::cout << "Colname: " << ind.first << std::endl;
            ind.second.printIndex();
            std::cout << "----------------------------------------\n" << std::endl;
        }
    }
};

