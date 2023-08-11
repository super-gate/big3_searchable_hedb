#ifndef HDB_supergate
#define HDB_supergate

#include <helib/helib.h>

#include <iostream>
#include <deque>

#include "../comp_lib/comparator.h"
#include "../comp_lib/tools.h"

/**
 * \namespace HDB_supergate_
 * main namespace for all utility functions for a HEDB
*/
namespace HDB_supergate_{
    typedef std::vector<helib::Ctxt> Ctxt_vec;                      /**< a vector of ciphertexts, Ctxt_vec */
	typedef std::vector<std::vector<helib::Ctxt>> Ctxt_mat;         /**< a matrix of ciphertexts, Ctxt_mat */

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

    /**
     * \class PtxtIndex
     * \brief class representing a plaintext index
     * 
     * A plaintext index is a collection of <key, [uid]> pairs, so each key is mapped to a list of uids that describe
     * rows in the DB. Key are currently represented as integers.
    */
    class PtxtIndex
    {
        private:
            std::vector<std::pair<long, std::vector<unsigned long>>> plaintext_index;   /**< the plaintext index */
            std::vector<long> keys;                                                     /**< separate collection of keys for convenience*/

            int c = 0;                                                                  /**< value representing the maximum length of [uids] array */
            int last_index;                                                             /**< value representing the most recently referenced key */

        public:
            void insert(long k, unsigned long v);                                       /**< inserts value v into key k */

            int R() {return keys.size();}                                               /**< returns the number of keys */
            int C() {return c;}                                                         /**< returns c, the maximum length of values array */
            std::vector<long> getKeys() {return keys;}                                  /**< returns the keys vector */
            
            // void sortKeys();                                                            /**< sorts the keys vector according to size of plaintext index vector in descending order */
            bool empty(long);                                                           /**< true if queried key does not have any values mapped to it*/
            long getSize(long);                                                         /**< gets the size of index vector for given key */
            long popBack(long, bool emty = false);                                      /**< removes the right-most key value from keys vector */
            void printIndex();                                                          /**< debug function to print the index */
    };

    /**
     * \class PtxtIndexFile
     * \brief class representing a collection of PtxtIndexes
     * 
     * The plaintext index file is the object representing lots of plaintext indexes. It is represented as a vector of 
     * <column name, PtxtIndex> pairs, with an index associated with each column of a DB.
    */
    class PtxtIndexFile
    {
        private:
            std::vector<std::pair<std::string, PtxtIndex>> IndexFile;                               /**< The IndexFile */
            std::vector<std::string> cols;                                                          /**< separate collection of column names */

        public:
            std::vector<std::pair<std::string, PtxtIndex>>& getIndexFile() {return IndexFile;}      /**< getter for the IndexFile */
            void insert(std::string col, long k, unsigned long v);                                  /** inserts for column col, key k, value v */

            void printIndex(std::string col);                                                       /**< debug function for printing a particular index, given column name*/
            void printIndexFile();                                                                  /**< debug function for printing the entire PtxtIndexFile*/
            void clear();
    };

    /**
     * \class CtxtIndex
     * \brief class representing an encrypted ciphertext index
     * 
     * A ciphertext index has a Ctxt_vec type of encrypted keys and Ctxt_mat type of encrypted uids.
     * The encrypted uids has dimension of X rows and Y columns.
    */
    class CtxtIndex
    {
        private:
            Ctxt_vec enc_key;               /**< the encrypted keys as vector of ciphertexts */
            Ctxt_mat enc_uid;               /**< the encrypted uids as matrix of ciphertexts */
            unsigned long X;                /**< the number of rows in the enc_uid */
            unsigned long Y;                /**< size of enc_key / number of columns in enc_uid */
            
        public:
            /**
             * \fn encrypt
             * \brief encrypts a plaintext index into ciphertext index
             * 
             * @param ptIndex the plaintext index
             * @param comparator reference to comparator class to encode the numbers into compatible format
             * @param contx crypto context for encryption
             * @param pk public key for encryption
             * @param input_range the integer upper bound for input
             * @param digit_base the modulo base for integer encoding
             * @param enc_base actual encryption base including d and l
             * @param exp_len expansion length l
             * @param nslots number of slots in a single ciphertext
             * @param max_per number of integers that fit in a single ciphertext
             * @param verbose verbose toggle
            */
            void encrypt(PtxtIndex ptIndex, 
                         he_cmp::Comparator& comparator,
                         const helib::Context& contx,
                         helib::PubKey& pk,
                         unsigned long input_range, 
                         unsigned long digit_base,
                         unsigned long enc_base,
                         unsigned long exp_len,
                         unsigned long nslots,
                         unsigned long max_per,
                         bool verbose
                         );
            Ctxt_vec& keys() {return enc_key;}      /**< getter for enc_key */
            Ctxt_mat& uids() {return enc_uid;}      /**< getter for enc_uid */
            unsigned long getX() {return X;}        /**< getter for X value */
            unsigned long getY() {return Y;}        /**< getter for Y value */

            void writeTo(std::ostream& os) const;                                       /**< binary serialization */
            void read(std::istream& is, helib::PubKey&);                                /**< binary deserialization */

            friend std::ostream& operator<<(std::ostream&, const CtxtIndex&);
    };

    /**
     * \class CtxtIndexFile
     * \brief class representing a ciphertext index file
     * 
     * A ciphertext intex file is a collection of CtxtIndexes. It is a collection of <column name, CtxtIndex> pairs, with
     * the column name and corresponding ciphertext index as a pair.
    */
    class CtxtIndexFile
    {
        private:
            std::vector<std::pair<std::string, CtxtIndex>> IndexFile;       /**< The Index File. TODO: should consider encrypting the column names as well. */
            std::vector<std::string> cols;                                  /**< seperate collection of column names*/

        public:
            /**
             * \fn encrypt
             * \brief encrypts a plaintext index file into ciphertext index file
             * 
             * @param ptIndexFile reference to the plaintext index file
             * @param comparator reference to comparator class to encode the numbers into compatible format
             * @param contx crypto context for encryption
             * @param pk public key for encryption
             * @param input_range the integer upper bound for input
             * @param digit_base the modulo base for integer encoding
             * @param enc_base actual encryption base including d and l
             * @param exp_len expansion length l
             * @param nslots number of slots in a single ciphertext
             * @param max_per number of integers that fit in a single ciphertext
             * @param verbose verbose toggle
            */
            void encrypt(PtxtIndexFile& ptIndexFile,
                         he_cmp::Comparator& comparator,
                         const helib::Context& contx,
                         helib::PubKey& pk,
                         unsigned long input_range, 
                         unsigned long digit_base,
                         unsigned long enc_base,
                         unsigned long exp_len,
                         unsigned long nslots,
                         unsigned long max_per,
                         bool verbose
                         );
            
            /**
             * \fn insert
             * \brief encrypts a plaintext index into ciphertext index
             * 
             * @param colname the column name to be inserted as
             * @param ptIndex the plaintext index
             * @param comparator reference to comparator class to encode the numbers into compatible format
             * @param contx crypto context for encryption
             * @param pk public key for encryption
             * @param input_range the integer upper bound for input
             * @param digit_base the modulo base for integer encoding
             * @param enc_base actual encryption base including d and l
             * @param exp_len expansion length l
             * @param nslots number of slots in a single ciphertext
             * @param max_per number of integers that fit in a single ciphertext
             * @param verbose verbose toggle
            */
            void insert(std::string colname, 
                        PtxtIndex& ptIndex,
                        he_cmp::Comparator& comparator,
                        const helib::Context& contx,
                        helib::PubKey& pk,
                        unsigned long input_range, 
                        unsigned long digit_base,
                        unsigned long enc_base,
                        unsigned long exp_len,
                        unsigned long nslots,
                        unsigned long max_per,
                        bool verbose
                        );
            void insert(std::string colname, CtxtIndex& index);         /**< Inserts CtxtIndex for given colname */

            std::vector<std::pair<std::string, CtxtIndex>> getIndexFile() {return IndexFile;}

            CtxtIndex& find(unsigned long);                                         /**< Finds the corresponding CtxtIndex given index of column */
            CtxtIndex& find(std::string);                                           /**< Finds the corresponding CtxtIndex given column name */
            unsigned long indexOf(std::string);                                     /**< Returns the index given the column name */
            void write_raw_index_file(std::ostream& os);                            /**< binary serialization of std::vector<std::pair<std::string, CtxtIndex>> object */
            void read_raw_index_file(std::istream& is, helib::PubKey&);             /**< binary deserialization of std::vector<std::pair<std::string, CtxtIndex>> object */
            void writeTo(std::ostream& os);                                         /**< binary serialization */
            void read(std::istream& is, helib::PubKey&);                            /**< binary deserialization */
            int size() {return IndexFile.size();}                                   /**< returns the current size of indexFile*/
            bool empty() {return IndexFile.size() == 0;}                            /**< return true if size is 0*/
            void clear();                                                           /**< clears out the indexfile*/

            friend std::ostream& operator<<(std::ostream&, const CtxtIndexFile&);   /**< custom serialization*/
    };

    /**
     * \class HEQuery
     * \brief Object representing a query object used to query the HEDB
    */
    class HEQuery {
        public:
        long source;                                    /**< The source column index. TODO: encrypt this too */
        helib::Ctxt query;                              /**< the query ciphertext */
        std::pair<helib::Ctxt, helib::Ctxt> Q_type;     /**< query type EQ <E(1), E(0)>, LT <E(0), E(1)>, or LEQ <E(1),E(1)> */
        std::vector<long> dest;                         /**< Collection of destination columns to query. TODO: encrypt these*/

        /**
         * Constructor of the HEQuery class
         * 
         * The constructor takes in the public key to initialize query ciphertext and query type ctxt pair.
         * @param pk reference to the public key
        */
        HEQuery(helib::PubKey& pk) : query(pk), Q_type(std::pair<helib::Ctxt, helib::Ctxt>(query, query)) {};

        /**
         * \fn insert
         * \brief inserts query information
         * 
         * @param src the source column. TODO: encrypt
         * @param EQ The ciphertext representing EQ type. Either E(1) or E(0)
         * @param LT The ciphertext representing LT type. Either E(1) or E(0)
         * @param qry The query ciphertext
         * @param dst the destination columns. TODO: encrpyt
        */
        void insert(long src,
                    helib::Ctxt& EQ,
                    helib::Ctxt& LT,
                    helib::Ctxt& qry,
                    std::vector<long> dst)
        {
            source = src;
            Q_type = std::pair<helib::Ctxt, helib::Ctxt>(EQ, LT);
            query = qry;
            dest = dst;
        }

        friend std::ostream& operator<<(std::ostream&, const HEQuery&);     /**< custom serialization*/
        void writeTo(std::ostream& os) const;                               /**< binary serialization */
        void read(std::istream& is);                                        /**< binary serialization */
        void readFrom(std::istream& is, helib::PubKey& pk);
    };

    /**
     * Query Mode Enum
     * Either normal query, query with extension field, or with indexfile
     * can be specified with the enum
    */
    enum Q_MODE {
        NORMAL,
        EXTF,
        IND
    };
    
    /**
     * Query Type Enum
     * A query can be equal EQ, less than LT, or less than or equal to LEQ.
     * MIN and MAX queries are not supported yet.
    */
    enum Q_TYPE_t {
        EQ,
        LT,
		LEQ,
        MIN,
        MAX
    };

    /**
     * BGV_param struct
     * A struct representing all necessary parameters to construct a BGV crypto context
     * and the necessary comparison logic.
    */
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

    bool operator==(const BGV_param& lhs, const BGV_param& rhs);

    const struct BGV_param STD128_HDB{
        167,     // p
        3,     // d
        28057,    // m
        800,     // nb_primes
        2,      // l
        3,      // c
        6,      // scale
        1,      // r
    };
    
    const struct BGV_param TOY_HDB{
        7,     // p
        3,     // d
        300,    // m
        600,     // nb_primes
        4,      // l
        3,      // c
        6,      // scale
        1,      // r
    };

    struct BGV_param MakeBGVParam(long, long, long, long, long, long, long, long);  /**< function to create BGV_Param given parameters */
    
    helib::Context MakeBGVContext(long, long, long, long, long, long);              /**< function to create a helib::Context given parameters */
 
    helib::Context MakeBGVContext(const struct BGV_param);                          /**< function to create a helib::Context given BGV_Param struct */

    helib::Context* MakeBGVContextPtr(long, long, long, long, long, long);
    helib::Context* MakeBGVContextPtr(const struct BGV_param);

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

    void write_raw_ctxt_mat(std::ostream& os, Ctxt_mat&);                           /**< binary serialization of Ctxt_mat type. Includes metadata information */
    void write_raw_ctxt_vec(std::ostream& os, Ctxt_vec&);                           /**< binary serialization of Ctxt_vec type. Includes metadata information */
    void read_raw_ctxt_mat(std::istream& is, Ctxt_mat&, helib::PubKey&);            /**< binary deserialization of Ctxt_mat type. Includes metadata information */
    void read_raw_ctxt_vec(std::istream& is, Ctxt_vec&, helib::PubKey&);            /**< binary deserialization of Ctxt_vec type. Includes metadata information */

    void write_raw_string(std::ostream& os, std::string& s);                        /**< binary serialization of string */
    void write_raw_string_vector(std::ostream& os, std::vector<std::string>& sv);   /**< binary serialization of string vector */
    std::string read_raw_string(std::istream& is);                                  /**< binary deserialization of string */
    void read_raw_string_vector(std::istream& is, std::vector<std::string>& sv);    /**< binary deserialization of string vector*/

    /**
     * \fn setIndexParams
     * \brief helper function for setting X and Y, parameters needed for creating the encrypted index file
     * 
     * @param R the R value
     * @param C the C value
     * @param max_per maximum number of integers that fit in one ciphertext
     * @param X reference to X=min(R,C)
     * @param Y reference to Y=R >= C ? ceil(R/max_per) : ceil(C/max_per)
     * @param verbose verbose toggle
    */
    void setIndexParams(unsigned long, 
                        unsigned long, 
                        unsigned long, 
                        unsigned long&, 
                        unsigned long&,
                        bool);

    /**
     * \fn dataToZZXSlot
     * \brief helper function to encode integer data into a compatible plaintext format
     * 
     * @param data the integer data
     * @param dest reference to the plaintext polynomial vector that the data will be encoded into
     * @param counter utility variable to count when the data needs to be converted
     * @param digit_base the modulo base of the system
     * @param exp_len the expansion length l
     * @param enc_base the encryption base of the system
     * @param comparator reference to the comparator for encoding
    */
    void dataToZZXSlot(unsigned long data,
                       vector<ZZX>& dest,
                       unsigned long counter,
                       unsigned long digit_base,
                       unsigned long exp_len,
                       unsigned long enc_base,
                       he_cmp::Comparator& comparator
                       );
    
    /**
     * \fn encryptAndInsert
     * \brief helper function encrypting the plaintext and inserting into the destination ciphertext vector
     * 
     * @param contx reference to the crypto context for encryption
     * @param pk reference to the public key for encryption
     * @param ptxt reference to the plaintext
     * @param dest reference to the Ctxt_vec that the plaintext will be inserted into
    */
    void encryptAndInsert(const helib::Context& contx,
                          helib::PubKey& pk,
                          std::vector<NTL::ZZX>& ptxt,
                          Ctxt_vec& dest);

    /**
     * \fn findNSlots
     * \brief utility function of finding the number of slots for a ciphertext given its parameters
     * 
     * @param p plaintext modulus
     * @param m another BGV parameter
     * @returns the number of slots
    */
    long findNSlots(long, long);
};
#endif


