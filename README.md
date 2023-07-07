# HOW TO RUN

Searchable DB Library Install
```bash
cd ./big3_searchable_hedb/HDB_comparison_library
rm -r build
mkdir build
cd build
```
If HElib is installed as a library...
```bash
cmake ..
```
If HElib is locally installed...
```bash
cmake -Dhelib_DIR=/{PATH}/helib_install/helib_pack/share/cmake/helib ..
```
then
```bash
make install
```
installs the HDB library in the folder ./big3_searchable_hedb/lib_HDB

To run main code...
```bash
cd ./big3_searchable_hedb
rm -r build
mkdir build
cd build
```
then run cmake and make as above. Compiled binary will be in ./big3_searchable_hedb/bin

# API
Can be found in the ./html directory. Open index.html to access the API documentation.