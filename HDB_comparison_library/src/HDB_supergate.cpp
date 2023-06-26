#include "HDB_supergate.hpp"

using namespace helib;
using namespace std;
using namespace he_cmp;
using namespace NTL;

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

    bool PtxtIndex::empty(long key) {
        auto it = std::find(keys.begin(), keys.end(), key);
        if (it == keys.end()) 
        {cout << "unfound key: " << key << endl; throw runtime_error("Cannot find key in index"); }

        last_index = int(it - keys.begin());
        return plaintext_index[last_index].second.empty();
    }

    long PtxtIndex::popBack(long key, bool emty)
    {
        //should be called with empty=true if empty(long) was called before
        if (!emty) //if empty was not called
        {
            if (empty(key)) return -1;
        }
        long val = plaintext_index[last_index].second.back();
        plaintext_index[last_index].second.pop_back();
        return val;
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

    void setIndexParams(unsigned long R, 
                        unsigned long C, 
                        unsigned long nslots, 
                        unsigned long& X, 
                        unsigned long& Y,
                        bool verbose)
    {
        if (verbose)
            cout << "R: " << R << ", C: " << C << endl;
        X = min(R, C);
        Y = R >= C ? ceil(float(R) / nslots) : ceil(float(C) / nslots);
    }

    void dataToZZXSlot(unsigned long data,
                       vector<ZZX>& dest,
                       unsigned long counter,
                       unsigned long digit_base,
                       unsigned long exp_len,
                       unsigned long enc_base,
                       Comparator& comparator
                       ) 
    {
        vector<long> decomp_data;
        ZZX slot;

        digit_decomp(decomp_data, data, digit_base, exp_len);
        for(unsigned long l = 0; l < exp_len; ++l)
        {
            comparator.int_to_slot(slot, decomp_data[l], enc_base);
            dest[counter*exp_len + l] = slot;
        }
    }

    void encryptAndInsert(const Context& contx,
                          PubKey& pk,
                          vector<ZZX>& ptxt,
                          Ctxt_vec& dest)
    {
        Ctxt ctxt(pk);
        contx.getView().encrypt(ctxt, pk, ptxt);
        dest.push_back(ctxt);
    }

    void CtxtIndex::encrypt(PtxtIndex ptxt_index, 
                            Comparator& comparator,
                            const Context& contx,
                            PubKey& pk,
                            unsigned long input_range, 
                            unsigned long digit_base,
                            unsigned long enc_base,
                            unsigned long exp_len,
                            unsigned long nslots,
                            unsigned long max_per,
                            bool verbose
                            )
    {
        setIndexParams(ptxt_index.R(), ptxt_index.C(), nslots, X, Y, verbose);

        enc_key.reserve(Y);
        enc_uid.resize(X);
        for (auto& uid: enc_uid) uid.reserve(Y);

        deque<long> key_queue;
        for (long k: ptxt_index.getKeys()) key_queue.push_back(k);

        vector<ZZX> ptxt_key;
        vector<vector<ZZX>> ptxt_uid;

		unsigned long counter = 0;
        while (!key_queue.empty())
        {
            
            unsigned long k = key_queue.front();
            key_queue.pop_front();

            if (!k) continue; //k == 0
            
            if (!counter) //reset at counter == 0
            {
                ptxt_key.clear();
                ptxt_key.resize(nslots);
                ptxt_uid.clear();
                ptxt_uid.resize(X);
                for (auto& row : ptxt_uid) row.resize(nslots);
            }
            
            //encode key
            dataToZZXSlot(k % input_range,
                          ptxt_key,
                          counter,
                          digit_base,
                          exp_len,
                          enc_base,
                          comparator);

            for (unsigned long i = 0; i < X; ++i)
            {
                if (ptxt_index.empty(k)) break;
                unsigned long v = ptxt_index.popBack(k, true);
                dataToZZXSlot(v % input_range,
                              ptxt_uid[i],
                              counter,
                              digit_base,
                              exp_len,
                              enc_base,
                              comparator);
            }
            counter++;
            if (counter == max_per)
			{
                encryptAndInsert(contx, pk, ptxt_key, enc_key); //key
                for (unsigned long i = 0; i < X; ++i)
                    encryptAndInsert(contx, pk, ptxt_uid[i], enc_uid[i]); //uids

				counter = 0;
                ptxt_key.clear();
				ptxt_uid.clear();
			}
            if (!ptxt_index.empty(k))
            {
                while (key_queue.size() < X - 1) key_queue.push_back(long(0));
                key_queue.push_back(k);
            }
        }
        if (counter < max_per)
        {
            encryptAndInsert(contx, pk, ptxt_key, enc_key); //key
            for (unsigned long i = 0; i < X; ++i)
                encryptAndInsert(contx, pk, ptxt_uid[i], enc_uid[i]); //uids
        }
        if (verbose)
        {
            cout << "\nkey size: " << enc_key.size()
                 << "\nindex size: " << enc_uid.size()
                 << "\nindex[0] size: " << enc_uid[0].size() 
                 << "\nX: " << X << ", Y: " << Y << endl;
        }
        
    }

    void CtxtIndexFile::encrypt(PtxtIndexFile& ptxt_index_file,
                                Comparator& comparator,
                                const Context& contx,
                                PubKey& pk,
                                unsigned long input_range, 
                                unsigned long digit_base,
                                unsigned long enc_base,
                                unsigned long exp_len,
                                unsigned long nslots,
                                unsigned long max_per,
                                bool verbose
                                )
    {
        for (auto& pair: ptxt_index_file.getIndexFile())
            insert(pair.first,
                   pair.second,
                   comparator,
                   contx,
                   pk,
                   input_range,
                   digit_base,
                   enc_base,
                   exp_len,
                   nslots,
                   max_per,
                   verbose);
    }

    void CtxtIndexFile::insert(std::string col, 
                               PtxtIndex& ptxt_index,
                               Comparator& comparator,
                               const Context& contx,
                               PubKey& pk,
                               unsigned long input_range, 
                               unsigned long digit_base,
                               unsigned long enc_base,
                               unsigned long exp_len,
                               unsigned long nslots,
                               unsigned long max_per,
                               bool verbose
                               )
    {
        CtxtIndex ctxt_index;
        ctxt_index.encrypt(ptxt_index,
                           comparator,
                           contx,
                           pk,
                           input_range,
                           digit_base,
                           enc_base,
                           exp_len,
                           nslots,
                           max_per,
                           verbose);
        insert(col, ctxt_index);
    }
    
    void CtxtIndexFile::insert(std::string col, CtxtIndex& ctxt_index)
    {
        IndexFile.emplace_back(pair(col, ctxt_index));
    }

    CtxtIndex& CtxtIndexFile::find(unsigned long i)
    {
        return IndexFile[i].second;
    }

    CtxtIndex& CtxtIndexFile::find(string colname)
    {
        return IndexFile[indexOf(colname)].second;
    }

    unsigned long CtxtIndexFile::indexOf(string colname)
    {
        auto it = std::find(cols.begin(), cols.end(), colname);
        if (it == cols.end())
        {
            cout << "Cannot find index for the column..." << endl;
            return cols.size();
        }
        return ulong(it - cols.begin());
    }
};

