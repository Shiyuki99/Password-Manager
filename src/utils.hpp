#ifndef UTILS_HPP
#define UTILS_HPP

#include <string>
#include <iostream>

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

#endif