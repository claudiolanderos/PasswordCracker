//
//  HashDictionary.cpp
//  password-mac
//
//  Created by Claudio Landeros on 9/23/16.
//  Copyright © 2016 Sanjay Madhav. All rights reserved.
//

#include "HashDictionary.h"
#include "Timer.h"
#include "Sha1.h"
#include <string>
#include <fstream>

HashDictionary::HashDictionary()
{
    mHashMap = new std::unordered_map<std::string, std::string>();
    mHashMap->rehash(100000); //performance boost
    mDecryptedMap = new std::map<int, std::pair<std::string, std::string> >();
    mFoundMap = new std::map<int, std::pair<std::string, std::string>* >();
    mUnsolvedPasswords = new std::vector<std::pair<int, std::string> >();
}

HashDictionary::~HashDictionary(){
    
    if(mHashMap != nullptr)
    {
        mHashMap->clear();
        delete mHashMap;
        mHashMap = nullptr;
    }
}

void HashDictionary::PrintPasswords(std::string path)
{
    std::ofstream output(path, std::ios::out|std::ios::binary|std::ios::trunc);
    if(!output.is_open())
    {
        std::cout<<"Error opening output file!" << std::endl;
        return;
    }
    
    for(auto it = mDecryptedMap->begin(); it != mDecryptedMap->end(); it++)
    {
        output << it->second.first;
        output << ",";
        output << it->second.second;
        output << "\n";
    }
    output.close();
}
void HashDictionary::EncryptDictionary(std::istream &dictionaryFile)
{
    std::string password;
    unsigned char hash[20];
    char hex_str[41];
    Timer timer;
 
    timer.start();
    while(std::getline(dictionaryFile, password))
    {
        sha1::calc(password.c_str(), password.length(), hash);
        sha1::toHexString(hash, hex_str);
        mHashMap->operator[](std::string(hex_str)) = password;
    }
    double elapsed = timer.getElapsed();
    std::cout<<"Time elapsed encrypting: " << elapsed << std::endl;
    
}

void HashDictionary::DecryptDictionary(std::istream &passwordsFile)
{
    
    std::unordered_map<std::string, std::string>::iterator it;
    std::string hashedPassword;
    int count = 0;
    while(std::getline(passwordsFile, hashedPassword))
    {
        it = mHashMap->find(hashedPassword);
        if(it == mHashMap->end())   //not found
        {
            mUnsolvedPasswords->push_back(std::make_pair(count, hashedPassword));
            mDecryptedMap->operator[](count) = std::make_pair(hashedPassword, "??");
        }
        else{
            mDecryptedMap->operator[](count) = std::make_pair(hashedPassword, it->second);
            mFoundMap->operator[](count) = &mDecryptedMap->find(count)->second;     //can be improved
        }
        count++;
    }
    BruteForce();
}

void HashDictionary::BruteForce()
{
    int count;
    int temp = 0;
    std::string hashedPassword;
    int countingMachine[4] = {0,0,0,0};
    char passwordAttempt[4] = {'\0', '\0', '\0', '\0'};
    unsigned char hash[20];
    char hex_str[41];
    Timer timer;
    
    timer.start();
    for(auto it = mUnsolvedPasswords->begin(); it != mUnsolvedPasswords->end(); ++it)
    {
        count = it->first;
        hashedPassword = it->second;
    
        int length = 0;
        
        while(countingMachine[0] != 36 && length < 4)
        {
            countingMachine[length] += 1;
            if(countingMachine[length] == 36)
            {
                temp = countingMachine[0];
                for(int i = length; i > 0; --i)
                {
                    if(countingMachine[i] != 36)
                    {
                        break;
                    }
                    countingMachine[i] = 0;
                    countingMachine[i-1] += 1;
                }
                if(countingMachine[0] == 36)
                {
                    for(int i = 0; i < 4; ++i)
                    {
                        passwordAttempt[i] = '\0';
                        countingMachine[1] = 0;
                    }
                    ++length;
                    countingMachine[0] = 0;
                    if(length == 4)
                    {
                        break;
                    }
                }
            }

            
            for(int i = 0; i <= length; ++i)
            {
                passwordAttempt[i] = countingMachineArray[countingMachine[i]];
            }
            sha1::calc(passwordAttempt, length+1, hash);
            sha1::toHexString(hash, hex_str);
            std::string temp = std::string(hex_str);
            if(std::string(hex_str) == hashedPassword) //found!
            {
                mDecryptedMap->operator[](count) = std::make_pair(it->second, std::string(passwordAttempt, length+1));

            }
        }
    }
    double elapsed = timer.getElapsed();
    std::cout<<"Time elapsed brute forcing: " << elapsed << std::endl;
}
