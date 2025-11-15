#ifndef UTILS_HPP
#define UTILS_HPP

#include "stdlib_inc.hpp"

std::string safe_input(size_t max_len) {
   std::string input;
   std::getline(std::cin, input);
   while (input.size() > max_len) {
      std::cout << "Input too long! Maximum length is " << max_len << " characters. Please try again: ";
      std::getline(std::cin, input);
   }
   input = input.substr(0, max_len);
   return input;
}
auto presets = {
   "",

};

typedef struct Entry {
   std::string Name;
   std::string Username;
   std::string Website;
   std::string Password;
   time_t Modf_Time;
}Entry;

void Create_Password(std::string &password) {
   std::cout << "Press M to type password manually" << std::endl;
   std::cout << "Press G to Generate a password" << std::endl;
   std::cout << "Press X to Exit" << std::endl;
   char opt = '\0';
   std::cin >> opt;
   if (opt == 'g' || opt == 'G') {
      std::cout << "Please type all what you want to include from the list: " << std::endl;
      std::cout << "1- Alphabits [abc...] " << std::endl; // 97 - 122
      std::cout << "2- Cap Alphabits [ABC...] " << std::endl; // 65-90
      std::cout << "3- Numbers [0123...] " << std::endl; // 48 - 59
      std::cout << "4- Special Characters [^&!...] " << std::endl;
      // 33-47 + 58-64 + 91-96 + 123-127
      std::cout << "5- Extended ASCII [ùÿ£...] " << std::endl; //
      std::cout << "Press enter if you want to process with the default set[123]: " << std::endl;
      std::string param = safe_input(5);

      std::unordered_set<char> allowed = {
         '1',
         '2',
         '3',
         '4',
         '5' };

      std::vector<unsigned char> char_list = {};
      for (auto i : param) {
         if (!allowed.contains(i))
            std::cout << "Input " << i << " is an invalid input.(will be ignored)" << std::endl;
         else
            std::cout << "";
      }


   }
}

// entry struct: Name + Username + Email + Website + Password + Modf Date
void get_entry(Entry &entry) {

   entry.Name = safe_input(64);
   entry.Username = safe_input(64);
   entry.Website = safe_input(64);
   entry.Password = safe_input(64);

}
#endif