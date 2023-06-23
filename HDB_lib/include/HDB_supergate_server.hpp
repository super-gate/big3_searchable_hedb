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
        size_t X, Y;

        HDB_supergate_::Ctxt_vec ctxt_equal;
        HDB_supergate_::Ctxt_vec less_final;

        unsigned long _num_db_element;
        unsigned long _num_db_category;
        unsigned long _max_element;
        unsigned long _Row;
       
        unsigned long numbers_size = comparator.m_context.getNSlots() / comparator.m_expansionLen;

        bool verbose;


        public:
        explicit SERVER (he_cmp::Comparator&,
                         HDB_supergate_::Ctxt_mat&,
                         HDB_supergate_::CtxtIndexFile&,
                         bool);

        void Query(HDB_supergate_::HEQuery&, HDB_supergate_::Ctxt_mat&);
        void QueryWithIndex(HDB_supergate_::HEQuery&, HDB_supergate_::Ctxt_mat&);

        void Response(helib::Ctxt &query, HDB_supergate_::Q_TYPE_t);
        
        HDB_supergate_::Ctxt_vec less_vector();

        HDB_supergate_::Ctxt_vec equal_vector();

        HDB_supergate_::Ctxt_mat result_equal();

        HDB_supergate_::Ctxt_mat result_less();

        unsigned long row();

        unsigned long category();

        unsigned long element();
    };
};

#endif


