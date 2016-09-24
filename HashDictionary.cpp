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
#include <tbb/parallel_invoke.h>

HashDictionary::HashDictionary()
{
    mHashMap = new std::unordered_map<std::string, std::string>();
    mHashMap->rehash(100000); //performance boost
    mDecryptedMap = new tbb::concurrent_unordered_map<int, std::pair<std::string, std::string> >();
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
    
    for(int count = 0; count < mDecryptedMap->size(); ++count)
    {
        auto it = mDecryptedMap->find(count);
        if(it != mDecryptedMap->end())
        {
            output << it->second.first;
            output << ",";
            output << it->second.second;
            output << "\n";
        }
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
    
    const int   start1[]    = {0,0,0,0},
                end1[]      = {3,35,35,35},
                start2[]    = {4,0,0,0},
                end2[]      = {7,35,35,35},
                start3[]    = {8,0,0,0},
                end3[]      = {11,35,35,35},
                start4[]    = {12,0,0,0},
                end4[]      = {15,35,35,35},
                start5[]    = {16,0,0,0},
                end5[]      = {19,35,35,35},
                start6[]    = {20,0,0,0},
                end6[]      = {23,35,35,35},
                start7[]    = {24,0,0,0},
                end7[]      = {27,35,35,35},
                start8[]    = {28,0,0,0},
                end8[]      = {31,35,35,35},
                start9[]    = {32,0,0,0},
                end9[]      = {35,35,35,35};
    
    Timer timer;
    timer.start();
    tbb::parallel_invoke(
                         [this, start1, end1] {BruteForce(start1, end1); },
                         [this, start2, end2] {BruteForce(start2, end2); },
                         [this, start3, end3] {BruteForce(start3, end3); },
                         [this, start4, end4] {BruteForce(start4, end4); },
                         [this, start5, end5] {BruteForce(start5, end5); },
                         [this, start6, end6] {BruteForce(start6, end6); },
                         [this, start7, end7] {BruteForce(start7, end7); },
                         [this, start8, end8] {BruteForce(start8, end8); },
                         [this, start9, end9] {BruteForce(start9, end9); }
                         );
    double elapsed = timer.getElapsed();
    std::cout<<"Time elapsed brute forcing: " << elapsed << std::endl;
}

void HashDictionary::BruteForce(const int start[4], const int end[4])
{
    int length = 0;
    std::string hashedPassword;
    int countingMachine[4];
    char passwordAttempt[4] = {'\0', '\0', '\0', '\0'};
    unsigned char hash[20];
    char hex_str[41];
    
    countingMachine[0] = start[0];
    countingMachine[1] = start[1];
    countingMachine[2] = start[2];
    countingMachine[3] = start[3];
    
    while(countingMachine[0] != (end[0])+1 && length < 4)
    {
        countingMachine[length] += 1;
        if(countingMachine[length] == 36)
        {
            for(int i = length; i > 0; --i)
            {
                if(countingMachine[i] != 36)
                {
                    break;
                }
                countingMachine[i] = 0;
                countingMachine[i-1] += 1;
            }
            if(countingMachine[0] == (end[0])+1)
            {
                for(int i = 0; i < 4; ++i)
                {
                    passwordAttempt[i] = '\0';
                    countingMachine[i] = 0;
                }
                ++length;
                countingMachine[0] = 0;
                if(length == 4)
                {
                    length = 0;
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
        
        for(auto it = mUnsolvedPasswords->begin(); it != mUnsolvedPasswords->end(); ++it)
        {
            if((*it).second == std::string(hex_str))
            {
                mDecryptedMap->operator[]((*it).first) = std::make_pair((*it).second, std::string(passwordAttempt, length+1));
            }
        }
    }
}
