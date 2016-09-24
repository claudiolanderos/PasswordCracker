// Main.cpp : Defines the entry point for the console application.
//
#include <iostream>
#include <string>
#include <fstream>
#include "Sha1.h"
#include "HashDictionary.h"

int main(int argc, char* argv[])
{
    if (argc == 2)
    {
        unsigned char hash[20];
        sha1::calc(argv[1], 4, hash);
        char hex_str[41];
        sha1::toHexString(hash, hex_str);
        std::cout<<hex_str<<std::endl;
    }
    else if (argc == 3)
    {
        std::string dictionaryPath = argv[1];
        std::string passwordPath = argv[2];
        std::ifstream dictionaryFile;
        std::ifstream passwordFile;
        
        dictionaryFile.open(dictionaryPath);
        passwordFile.open(passwordPath);
        if (dictionaryFile.is_open() && passwordFile.is_open())
        {
            HashDictionary hashDictionary;
            hashDictionary.EncryptDictionary(dictionaryFile);
            hashDictionary.DecryptDictionary(passwordFile);
            hashDictionary.PrintPasswords("pass_solved.txt");
        }
        else{
            std::cout<<"Error opening files";
        }
    }
    else
    {
        
    }
	return 0;
}

