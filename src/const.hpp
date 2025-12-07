#ifndef CONST_HPP
#define CONST_HPP

constexpr int SIGNATURE_SIZE = 8;
constexpr int VERSION_SIZE = 8;
constexpr int NAME_SIZE = 32;
constexpr int PASSWORD_SIZE = 32;
constexpr int HEADER_SIZE = 128;
constexpr int ENTRY_SIZE = 256;
constexpr char SIGNATURE[SIGNATURE_SIZE] = "SHPD";
constexpr char CURR_VERSION[VERSION_SIZE] = "0.1";

#endif