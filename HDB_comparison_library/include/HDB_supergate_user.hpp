#ifndef HDB_supergate_user
#define HDB_supergate_user

#include <helib/helib.h>
#include "../comp_lib/comparator.h"
#include "../comp_lib/tools.h"
#include "HDB_supergate.hpp"

/**
 * \namespace HDB_supergate_user_
 * \brief Namespace for the USER class
*/
namespace HDB_supergate_user_{
    /**
     * \class USER
     * \brief Class that simulates the USER that queries the DB
     * 
     * USER class simulates the TEE and contains both public and secret keys. It can construct query objects
     * and encrypt plaintext database to send to the SERVER class. 
    */
    class USER {
        public:
        he_cmp::Comparator& comparator;                                                     /**< comparator object */
        const helib::Context& contx;                                                        /**< crypto-context */
        helib::PubKey& pk;                                                                  /**< public key */
        helib::SecKey& sk;                                                                  /**< secret key */

        HDB_supergate_::PtxtIndexFile ptxt_index_file;                                      /**< the plaintext index file*/
        
        const helib::EncryptedArray& ea = contx.getView();                                  /**< encrypted array class used to encrypt and decrypt ciphertexts*/
        unsigned long p = contx.getP();                                                     /**< plaintext modulus p */
        unsigned long ord_p = contx.getOrdP();                                              /**< multiplicative order of p mod m */
        unsigned long nslots = contx.getNSlots();                                           /**< number of slots for this context */
        unsigned long exp_len = comparator.m_expansionLen;                                  /**< the expansion length l */
        unsigned long max_packed = nslots / exp_len;                                        /**< number of data that can be packed in a single ciphertext */
        unsigned long enc_base = (p + 1) >> 1;                                              /**< encryption base. (p+1)/2 for univariate circuit */
        unsigned long digit_base = power_long(enc_base, comparator.m_slotDeg);              /**< the actual digit base after d*/
        int space_bit_size = static_cast<int>(ceil(exp_len * log2(digit_base)));            /**< the bit size of the current context*/
        unsigned long input_range = space_bit_size < 64 ? power_long(digit_base, exp_len)   /**< the maximum input current context can handle*/
                                                        : ULONG_MAX;

        bool verbose;                                                                       /**< verbose flag */

        /**
         * \fn EncryptNumber
         * \brief Creates a ciphertext with slots filled with the specified integer. Creates E(N) for N.
         * 
         * @param ctxt ciphertext that is populated
         * @param i integer to be inserted
        */
        void EncryptNumber(helib::Ctxt& ctxt, unsigned long i);
        void EncryptNumberPerSlot(helib::Ctxt& ctxt, unsigned long i);

        public:
        /**
         * Constructor for the USER class
         * @param comparator reference to comparator object
         * @param contx reference to the crypto-context
         * @param pk reference to the public key object
         * @param sk reference to the secret key object
        */
        explicit USER(
            he_cmp::Comparator& comparator,
            const helib::Context& contx,
            helib::PubKey& pk,
            helib::SecKey& sk,
            bool
        );

        /**
         * \fn createPtxtIndexFile
         * \brief parses the csv from filename and constructs a PtxtIndexFile object
         * 
         * @param filename file path to the raw csv data
        */
        void createPtxtIndexFile(string filename);
        /**
         * \fn createCtxtIndexFile
         * \brief encrypts the PtxtIndexFile into CtxtIndexFile
         * 
         * @param IndexFile reference to the CtxtIndexFile to be populated
        */
        void createCtxtIndexFile(HDB_supergate_::CtxtIndexFile& IndexFile);

        /**
         * \fn ConstructQuery
         * \brief constructs a query object based on parameters
         * 
         * @param query reference to the query object to be populated
         * @param input the input integer query
         * @param type the type of the query to be executed in enum Q_TYPE_t
         * @param source the integer index of source column to be queried from
         * @param dest vector of integer indices of destination columns to be queried
        */
        void ConstructQuery(HDB_supergate_::HEQuery& query,
                            unsigned long input,
                            HDB_supergate_::Q_TYPE_t type,
                            unsigned long source, //TODO: change this to query names from just indices maybe?
                            std::vector<unsigned long> dest);

        /**
         * \fn csvToDB
         * \brief function to encrypt all plaintext data into ciphertext and save into a Ctxt_mat datatype
         * 
         * @param DB the referecnce to the Ctxt_mat datatype we are saving all ciphertext into
         * @param range the CSVRange object that reads the csvfile
        */
        void csvToDB(HDB_supergate_::Ctxt_mat& DB, 
                     HDB_supergate_::CSVRange& range);

        /**
         * used to convert csv files without headers
         * @param DB the referecnce to the Ctxt_mat datatype we are saving all ciphertext into
         * @param path file path of the csv file
        */
        void csvToDB(HDB_supergate_::Ctxt_mat& DB, 
                     std::string path);

        /**
         * used to convert csv files with headers into ciphertext DB
         * @param DB the referecnce to the Ctxt_mat datatype we are saving all ciphertext into
         * @param path file path of the csv file
         * @param headers reference to the container of headers
        */
        void csvToDB(HDB_supergate_::Ctxt_mat& DB, 
                     std::string path, 
                     std::vector<std::string>& headers);
        
        unsigned long max();                                                            /**< returns input_range */

        HDB_supergate_::PtxtIndexFile getPtxtIndexFile() {return ptxt_index_file;}      /**< returns the plaintext index file */
        void printZZXasINT(vector<ZZX>);
        void printDecryptedINT(helib::Ctxt& ctxt);                                         /**< debug function to decrypt and print the ciphertext*/
        void printDecryptedZZX(helib::Ctxt& ctxt);
        void printCtxtMatINT(HDB_supergate_::Ctxt_mat&);                                   /**< debug function to decrypt and print a Ctxt_mat type object*/
        void printCtxtMatZZX(HDB_supergate_::Ctxt_mat&);
    };
};

#endif


