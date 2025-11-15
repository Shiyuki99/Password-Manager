#include <iostream>

#include "stdlib_inc.hpp"
#include "hash.hpp"
#include "vault_handler.hpp"




class Start {

public:
   Start() {
      std::cout << "Hello To Password Manager:" << std::endl;
      std::cout << "[1] Open Existsing Database." << std::endl;
      std::cout << "[2] Create New Database." << std::endl;
      std::cout << "[3] Exit." << std::endl;
      int mod;
      std::cin >> mod;
      switch (mod) {
      case 1:
         Open_Database();
         break;
      case 2:

      case 3:

      default:
         std::cout << "Wrong Value FCK OFF!<3" << std::endl;
      }
   }


private:
   static const int keySize = 99;
   static const int HEADER_SIZE = 128;
   std::string key[keySize];
   /**
    * @brief Open passwords database
    *
    * @return true Database opened successfully
    * @return false Error while trying to open Database:(
    */
   bool Open_Database() {
      //code later to open recent databases which a a bit lazy to do
      std::cout << "Please Enter Database Path: ";
      std::string path;
      std::cin >> path;

      std::FILE *file = fopen(path.c_str(), "rb");
      if (!file) {
         std::cerr << "FAILED TO OPEN FILE AT PATH: " << path << std::endl;
         return false;
      }
      char *buffer = (char *)malloc(keySize);
      if (!buffer) {
         std::cerr << "FAILED TO ALLOCATE BUFFER!" << std::endl;
         fclose(file);
         return false;
      }
      //Read_Header(file);
      auto bytesRead = fread(buffer, 1, keySize, file);
      if (bytesRead != keySize) {
         std::cerr << "BYTES READ WENT WRONG" << std::endl;
         std::cerr << "EXPECTED: " << keySize << " READ: " << bytesRead << std::endl;
         fclose(file);
         free(buffer);
         return false;
      }

      if (argon2id_Verifier(buffer))
         return 0;

      std::cout << "Open success:D" << std::endl;

      fseek(file, 1, 0);
      std::fclose(file);
      free(buffer);


      return true;
   }
};

int main(int argc, char **argv) {
   //Start start;
   //std::cout << argon2id_hash("Hello") << std::endl;
   return 0;
}
