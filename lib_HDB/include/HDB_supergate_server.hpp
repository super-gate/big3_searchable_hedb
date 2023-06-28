#ifndef HDB_supergate_server
#define HDB_supergate_server

#include <helib/helib.h>
#include "HDB_supergate.hpp"
#include "../comp_lib/comparator.h"
#include "../comp_lib/tools.h"

namespace HDB_supergate_server_{
    class SERVER {
        private:
            he_cmp::Comparator& comparator;
            HDB_supergate_::Ctxt_mat& DB;
            HDB_supergate_::CtxtIndexFile& IndexFile;
            size_t Row, Col;

            HDB_supergate_::Ctxt_vec v1_j;
        
            bool verbose;

        public:
            explicit SERVER(he_cmp::Comparator&,
                            HDB_supergate_::Ctxt_mat&,
                            HDB_supergate_::CtxtIndexFile&,
                            bool);

            void Query(HDB_supergate_::HEQuery&, HDB_supergate_::Ctxt_mat&);
            void QueryWithIndex(HDB_supergate_::HEQuery&, HDB_supergate_::Ctxt_mat&);
    };
};

#endif


