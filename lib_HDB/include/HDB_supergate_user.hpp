#ifndef HDB_supergate_user
#define HDB_supergate_user

#include <helib/helib.h>
#include "../comp_lib/comparator.h"
#include "../comp_lib/tools.h"
#include "HDB_supergate.hpp"

namespace HDB_supergate_user_{
    class USER {
        private:
        he_cmp::Comparator& comparator;
        const helib::Context& contx;
        helib::PubKey& pk;
        helib::SecKey& sk;

        HDB_supergate_::PtxtIndexFile ptxt_index_file;
        
        const helib::EncryptedArray& ea = contx.getView();
        unsigned long p = contx.getP();
        unsigned long ord_p = contx.getOrdP();
        unsigned long nslots = contx.getNSlots();
        unsigned long exp_len = comparator.m_expansionLen;
        unsigned long max_packed = nslots / exp_len;
        unsigned long enc_base = (p + 1) >> 1; // UNI
        unsigned long digit_base = power_long(enc_base, comparator.m_slotDeg);
        int space_bit_size = static_cast<int>(ceil(exp_len * log2(digit_base)));
        unsigned long input_range = space_bit_size < 64 ? power_long(digit_base, exp_len) : ULONG_MAX;

        bool verbose;

        void EncryptNumber(helib::Ctxt&, unsigned long);

        public:
        explicit USER(
            he_cmp::Comparator& comparator,
            const helib::Context& contx,
            helib::PubKey& pk,
            helib::SecKey& sk,
            bool
        );

        unsigned long max();

        HDB_supergate_::PtxtIndexFile getPtxtIndexFile() {return ptxt_index_file;}
        void createPtxtIndexFile(string);

        void createCtxtIndexFile(HDB_supergate_::CtxtIndexFile&);

        void ConstructQuery(HDB_supergate_::HEQuery&,
                            unsigned long,
                            HDB_supergate_::Q_TYPE_t,
                            unsigned long, //TODO: change this to query names from just indices maybe?
                            std::vector<unsigned long>);

        void csvToDB(HDB_supergate_::Ctxt_mat&, 
                     HDB_supergate_::CSVRange&);

        void csvToDB(HDB_supergate_::Ctxt_mat&, 
                     std::string path);

        void csvToDB(HDB_supergate_::Ctxt_mat&, 
                     std::string path, 
                     std::vector<std::string>&);
        
        void printDecrypted(helib::Ctxt& ctxt);
        void printCtxtMat(HDB_supergate_::Ctxt_mat&);
    };
};

#endif


