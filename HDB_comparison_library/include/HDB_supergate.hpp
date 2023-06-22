#ifndef HDB_supergate
#define HDB_supergate

#include <helib/helib.h>

#include <iostream>
#include <deque>

#include "../comp_lib/comparator.h"
#include "../comp_lib/tools.h"

namespace HDB_supergate_{
    typedef std::vector<helib::Ctxt> Ctxt_vec;
	typedef std::vector<std::vector<helib::Ctxt>> Ctxt_mat;

    class CSVRow
    {
        public:
            std::string_view operator[](std::size_t index) const
            {
                return std::string_view(&m_line[m_data[index] + 1], m_data[index + 1] -  (m_data[index] + 1));
            }
            std::size_t size() const
            {
                return m_data.size() - 1;
            }
            void readNextRow(std::istream& str)
            {
                std::getline(str, m_line);

                m_data.clear();
                m_data.emplace_back(-1);
                std::string::size_type pos = 0;
                while((pos = m_line.find(',', pos)) != std::string::npos)
                {
                    m_data.emplace_back(pos);
                    ++pos;
                }
                // This checks for a trailing comma with no data after it.
                pos   = m_line.size();
                m_data.emplace_back(pos);
            }
        private:
            std::string           m_line;
            std::vector<ulong>    m_data;
            
    };

    std::istream& operator>>(std::istream& str, CSVRow& data);

    class CSVIterator
    {   
        public:
            typedef std::input_iterator_tag     iterator_category;
            typedef CSVRow                      value_type;
            typedef std::size_t                 difference_type;
            typedef CSVRow*                     pointer;
            typedef CSVRow&                     reference;

            CSVIterator(std::istream& str)  :m_str(str.good()?&str:nullptr) { ++(*this); }
            CSVIterator()                   :m_str(nullptr) {}

            // Pre Increment
            CSVIterator& operator++()               {if (m_str) { if (!((*m_str) >> m_row)){m_str = nullptr;}}return *this;}
            // Post increment
            CSVIterator operator++(int)             {CSVIterator    tmp(*this);++(*this);return tmp;}
            CSVRow const& operator*()   const       {return m_row;}
            CSVRow const* operator->()  const       {return &m_row;}

            bool operator==(CSVIterator const& rhs) {return ((this == &rhs) || ((this->m_str == nullptr) && (rhs.m_str == nullptr)));}
            bool operator!=(CSVIterator const& rhs) {return !((*this) == rhs);}
        private:
            std::istream*       m_str;
            CSVRow              m_row;
    };

    class CSVRange
    {
        std::istream&   stream;
        public:
            CSVRange(std::istream& str)
                : stream(str)
            {}
            CSVIterator begin() const {return CSVIterator{stream};}
            CSVIterator end()   const {return CSVIterator{};}
    };

    class PtxtIndex
    {
        private:
            std::vector<std::pair<long, std::vector<unsigned long>>> plaintext_index; // [ <key, [uids]> ]
            std::vector<long> keys;

            int c = 0;
            int last_index;

        public:
            void insert(long k, unsigned long v);

            int R() {return keys.size();}
            int C() {return c;}
            std::vector<long> getKeys() {return keys;}
            
            bool empty(long);
            long popBack(long, bool emty = false);
            void printIndex();
    };

    class PtxtIndexFile
    {
        private:
            std::vector<std::pair<std::string, PtxtIndex>> IndexFile; //[ <colname, PtxtIndex> ]
            std::vector<std::string> cols;

        public:
            std::vector<std::pair<std::string, PtxtIndex>>& getIndexFile() {return IndexFile;}
            void insert(std::string col, long k, unsigned long v);

            void printIndex(std::string col);

            void printIndexFile();
    };

    class CtxtIndex
    {
        private:
            Ctxt_vec enc_key;
            Ctxt_mat enc_uid;
            
        public:
            void encrypt(PtxtIndex, 
                         he_cmp::Comparator&,
                         unsigned long input_range, 
                         unsigned long digit_base,
                         unsigned long enc_base,
                         unsigned long exp_len,
                         unsigned long nslots,
                         unsigned long max_per
                         );
    };

    class CtxtIndexFile
    {
        private:
            std::vector<std::pair<std::string, CtxtIndex>> IndexFile; //TODO: for now use string colnames, later encrypt this
            std::vector<std::string> cols;

        public:
            void encrypt(PtxtIndexFile&,
                         he_cmp::Comparator&,
                         unsigned long input_range, 
                         unsigned long digit_base,
                         unsigned long enc_base,
                         unsigned long exp_len,
                         unsigned long nslots,
                         unsigned long max_per
                         );
                          
            void insert(std::string, 
                        PtxtIndex&,
                        he_cmp::Comparator&,
                        unsigned long input_range, 
                        unsigned long digit_base,
                        unsigned long enc_base,
                        unsigned long exp_len,
                        unsigned long nslots,
                        unsigned long max_per
                        );
            void insert(std::string, CtxtIndex&);
    };

    
    /* Query Type */
    enum Q_TYPE_t {
        EQ,
        LT,
		EL,
        MIN,
        MAX
    };

    /* BGV Context Param*/
    struct BGV_param {
        long p;
        long d;
        long m;
        long nb_primes;
        long expansion_len;
        long c;
        long scale;
        long r;
    };
 
/*
	p: 167, d: 3, m: 28057, nb_primes: 538, c: 4, l: 3, scale: 6, r: 1
   */

    const struct BGV_param STD128_HDB{
        167,     // p
        3,     // d
        28057,    // m
        538,     // nb_primes
        3,      // l
        4,      // c
        6,      // scale
        1,      // r
    };
    
    const struct BGV_param TOY_HDB{
        7,     // p
        3,     // d
        300,    // m
        200,     // nb_primes
        3,      // l
        3,      // c
        6,      // scale
        1,      // r
    };

    struct BGV_param MakeBGVParam(long, long, long, long, long, long, long, long);
    
    helib::Context MakeBGVContext(long, long, long, long, long, long);
 
    helib::Context MakeBGVContext(const struct BGV_param);

    void setIndexParams(unsigned long, 
                        unsigned long, 
                        unsigned long, 
                        unsigned long&, 
                        unsigned long&);

    void dataToZZXSlot(unsigned long data,
                       vector<ZZX>& dest,
                       unsigned long counter,
                       unsigned long input_range,
                       unsigned long digit_base,
                       unsigned long exp_len,
                       unsigned long enc_base,
                       he_cmp::Comparator& comparator
                       );
    
    void encryptAndInsert(he_cmp::Comparator& comparator,
                          std::vector<NTL::ZZX>& ptxt,
                          Ctxt_vec& dest);

    long findNSlots(long, long);
};
#endif


