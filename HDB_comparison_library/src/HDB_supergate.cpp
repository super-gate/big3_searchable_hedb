#include "HDB_supergate.hpp"
#include "binio.h"

using namespace helib;
using namespace std;
using namespace he_cmp;
using namespace NTL;

namespace HDB_supergate_ {
    struct BGV_param MakeBGVParam(long p, 
                                  long d, 
                                  long m, 
                                  long nb_primes, 
                                  long expansion_len, 
                                  long c, 
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
            plaintext_index.emplace_back(std::pair<long, vector<unsigned long>>(k, new_vec));
            keys.push_back(k);
            if (!c) c = 1;
        }
        else 
        {
            int index = int(it - keys.begin());
            plaintext_index[index].second.emplace_back(v);
            int size = plaintext_index[index].second.size();
            if (size > c) c = size;
        }
    }

    // void PtxtIndex::sortKeys()
    // {
    //     // sort(keys.begin(), keys.end(), [](long k1, long k2)
    //     //                                 {
    //     //                                     return this.getSize(k1) > this.getSize(k2);
    //     //                                 });
    //     return;
    // }

    long PtxtIndex::getSize(long key)
    {
        if (empty(key)) return 0;
        return plaintext_index[last_index].second.size();
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
                        unsigned long max_per, 
                        unsigned long& X, 
                        unsigned long& Y,
                        bool verbose)
    {
        if (!verbose)
            cout << "R: " << R << ", C: " << C << ", max_per: " << max_per << endl;
        X = min(min(R, C), max_per);
        Y = R >= C ? ceil(float(R) / max_per) : ceil(float(C) / max_per);
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
        deque<long> key_queue;
        vector<long> sizes;
        for (long k: ptxt_index.getKeys()) 
        {
            key_queue.push_back(k);
            sizes.push_back(ptxt_index.getSize(k));
        }
        sort(key_queue.begin(), key_queue.end(), [&ptxt_index](long k1, long k2)
                                                    {
                                                        return ptxt_index.getSize(k1) > ptxt_index.getSize(k2);
                                                    });
        unsigned long sum = 0;

        X = max_per < ptxt_index.C() ? max_per : min(ptxt_index.R(), ptxt_index.C());
        for_each(sizes.begin(), sizes.end(), [&](auto& i) {sum += ceil(float(i) / X);});
        Y = ceil(float(sum) / max_per);
        
        enc_key.reserve(Y);
        enc_uid.resize(X);
        for (auto& uid: enc_uid) uid.reserve(Y);
        

        vector<ZZX> ptxt_key;
        vector<vector<ZZX>> ptxt_uid;

		unsigned long counter = 0;
        while (!key_queue.empty())
        {
            // cout << "key queue: " << key_queue.size() << ", " << key_queue.empty() << endl;
            // for (long x: key_queue) cout << x << ", ";
            // cout << endl;
            unsigned long k = key_queue.front();
            key_queue.pop_front();

            // if (!k) continue; //k == 0
            
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
                unsigned long v = k ? (!ptxt_index.empty(k) ? ptxt_index.popBack(k, true) : 0) : 0;
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
                // cout << ptxt_key << endl;
                // cout << "______________________________" << endl;
                // cout << ptxt_uid << endl;
                encryptAndInsert(contx, pk, ptxt_key, enc_key); //key
                for (unsigned long i = 0; i < X; ++i)
                    encryptAndInsert(contx, pk, ptxt_uid[i], enc_uid[i]); //uids

				counter = 0;
                ptxt_key.clear();
				ptxt_uid.clear();
			}
            if (!k) continue;
            if (!ptxt_index.empty(k))
            {
                while (key_queue.size() < X - 1) key_queue.push_back(long(0));
                auto it = key_queue.begin() + X - 1;
                while (it != key_queue.end())
                {
                    if (ptxt_index.getSize(*it) <= ptxt_index.getSize(k)) break;
                    it++;
                }
                key_queue.insert(it, k);
            }
        }
        if (counter && counter < max_per)
        {
            encryptAndInsert(contx, pk, ptxt_key, enc_key); //key
            for (unsigned long i = 0; i < X; ++i)
                encryptAndInsert(contx, pk, ptxt_uid[i], enc_uid[i]); //uids
        }
        if (enc_key.size() < Y)
        {
            // encrypt more to fill up Y
            ptxt_key.clear();
            ptxt_key.resize(nslots);
            encryptAndInsert(contx, pk, ptxt_key, enc_key); //key
            for (unsigned long i = 0; i < X; ++i)
                encryptAndInsert(contx, pk, ptxt_key, enc_uid[i]); //uids
        }
        if (verbose)
        {
            cout << "key size: " << enc_key.size()
                 << "\nindex size: " << enc_uid.size()
                 << "\nindex[0] size: " << enc_uid[0].size() 
                 << "\nX: " << X << ", Y: " << Y << endl;
        }
    }

    void CtxtIndex::writeTo(ostream& os) const
    {
        write_raw_int(os, X);
        write_raw_int(os, Y);
        write_raw_vector(os, enc_key);
        write_raw_int(os, enc_uid.size());
        for (auto& eu: enc_uid) write_raw_vector(os, eu);
    }

    void CtxtIndex::read(istream& is, PubKey& pk)
    {
        X = read_raw_int(is);
        Y = read_raw_int(is);
        Ctxt c(pk);
        read_raw_vector(is, enc_key, c);
        long size = read_raw_int(is);
        enc_uid.resize(size);
        for (auto& eu: enc_uid) read_raw_vector(is, eu, c);
    }

    ostream& operator<<(ostream& os, const CtxtIndex& ci)
    {
        os << "X: " << ci.X
           << ", Y: " << ci.Y << "\n";
        //ciphertexts are omitted
        return os;
    }
    
    ostream& operator<<(ostream& os, const CtxtIndexFile& file)
    {
        for (auto& ci: file.IndexFile)
        {
            os << "Column Name: " << ci.first
               << "\n    Dimensions: " << ci.second;
        }
        return os;
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
        cout << "Index File created for " << cols.size() << "columns."
             << "\nStatistics for each index:" << endl;
        unsigned long counter = 0;
        for (auto& pair: IndexFile)
        {
            unsigned long X = pair.second.getX();
            unsigned long Y = pair.second.getY();
            cout << "   Index for column " << pair.first << ": " << X << " rows(X) with " << Y << " ciphertexts(Y) each.\n"
                 << "       Total: XY + Y = " << (X*Y + Y) << " ciphertexts." << endl;
            counter += (X*Y+Y);
        }
        cout << "\nThis totals " << counter << " ciphertexts for the whole File.\n\n" << endl;
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
        IndexFile.emplace_back(pair<string, CtxtIndex>(col, ctxt_index));
        cols.push_back(col);
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

    void CtxtIndexFile::write_raw_index_file(ostream& os)
    {
        write_raw_int(os, IndexFile.size());
        for (auto& file: IndexFile)
        {
            write_raw_string(os, file.first);
            file.second.writeTo(os);
        }
    }

    void CtxtIndexFile::read_raw_index_file(istream& is, PubKey& pk)
    {
        long size = read_raw_int(is);
        while (size-- > 0)
        {
            string col = read_raw_string(is);
            CtxtIndex ci;
            ci.read(is, pk);
            IndexFile.emplace_back(col, ci);
        }
    }

    void CtxtIndexFile::writeTo(ostream& os) 
    {
        write_raw_string_vector(os, cols);
        write_raw_index_file(os);
    }
    void CtxtIndexFile::read(istream& is, PubKey& pk)
    {
        read_raw_string_vector(is, cols);
        read_raw_index_file(is, pk);
    }

    void CtxtIndexFile::clear()
    {
        IndexFile.clear();
        cols.clear();
    }

    template<typename T>
    void serialize_to_file(string filename, T& s)
    {
        ofstream of;
        of.open(filename, ios::out);
        if (of.is_open()) {
            // Write the context to a file
            s.writeTo(of);
            // Close the ofstream
            of.close();
        } else {
            stringstream ss;
            ss << "Cout not open file '" << filename << "'.";
            throw std::runtime_error(ss.str());
        }
    }

    void write_raw_ctxt_mat(std::ostream& os, Ctxt_mat& mat)
    {
        write_raw_int(os, mat.size());
        write_raw_int(os, mat[0].size());
        for (auto& v: mat)
            for (auto& c: v) c.writeTo(os);
    }

    void write_raw_ctxt_vec(std::ostream& os, Ctxt_vec& vec)
    {
        write_raw_vector(os, vec);
    }

    void read_raw_ctxt_mat(std::istream& is, Ctxt_mat& mat, PubKey& pk)
    {
        long X = read_raw_int(is);
        long Y = read_raw_int(is);
        mat.resize(X);
        Ctxt c(pk);
        for (auto& v: mat) v.resize(Y, c);
        for (auto& v: mat)
            for (auto& ct: v) ct.read(is);
    }

    void read_raw_ctxt_vec(std::istream& is, Ctxt_vec& vec, PubKey& pk)
    {
        Ctxt c(pk);
        read_raw_vector(is, vec, c);
    }

    void write_raw_string(std::ostream& os, std::string& s)
    {
        write_raw_int(os, s.length());
        os << s;
    }

    void write_raw_string_vector(std::ostream& os, std::vector<std::string>& sv)
    {
        write_raw_int(os, sv.size());
        for (auto& s: sv) write_raw_string(os, s);
    }

    std::string read_raw_string(std::istream& is)
    {
        long l = read_raw_int(is);
        char c[l];
        is.read(c, l);
        string s(c);
        return s;
    }

    void read_raw_string_vector(std::istream& is, std::vector<std::string>& sv)
    {
        long size = read_raw_int(is);
        sv.resize(size);
        for (auto& s: sv) s = read_raw_string(is);
    }

    ostream& operator<<(ostream& os, const HEQuery& q)
    {
        os << "Source Column: " << q.source
           << "\nDest Columns: ";
        for (auto& d: q.dest) os << d << ", ";
        //Ctxt needs to be decrypted, so omit
        return os;
    }

    void HEQuery::writeTo(ostream& os) const
    {
        write_raw_int(os, source);
        write_raw_vector(os, dest);
        query.writeTo(os);
        Q_type.first.writeTo(os);
        Q_type.second.writeTo(os);
    }

    void HEQuery::read(istream& is)
    {
        source = read_raw_int(is);
        read_raw_vector(is, dest);
        query.read(is);
        Q_type.first.read(is);
        Q_type.second.read(is);
    }

    void HEQuery::readFrom(istream& is, PubKey& pk)
    {
        source = read_raw_int(is);
        read_raw_vector(is, dest);
        query.readFrom(is, pk);
        Q_type.first.readFrom(is, pk);
        Q_type.second.readFrom(is, pk);
    }
};

