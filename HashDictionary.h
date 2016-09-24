//
//  HashDictionary.h
//  password-mac
//
//  Created by Claudio Landeros on 9/23/16.
//  Copyright © 2016 Sanjay Madhav. All rights reserved.
//

#include <stdio.h>
#include <iostream>
#include <unordered_map>
#include <vector>
#include <map>
#include <tbb/concurrent_unordered_map.h>

class HashDictionary
{
public:
    //Constructor for hash dictionary
    HashDictionary();
    
    ~HashDictionary();
    //Encrypt passwords from file
    void EncryptDictionary(std::istream &dictionaryFile);
    
    //Decrypt passwords from file
    void DecryptDictionary(std::istream &passwordsFile);
    
    void PrintPasswords(std::string path);
    
private:
    
    void BruteForce(const int start[4], const int end[4]);
    
    char countingMachineArray[37] = {'a', 'b', 'c', 'd', 'e', 'f',
                                        'g', 'h', 'i', 'j', 'k', 'l',
                                        'm', 'n', 'o', 'p', 'q', 'r',
                                        's', 't', 'u', 'v', 'w', 'x',
                                        'y', 'z', '0', '1', '2', '3',
                                        '4', '5', '6', '7', '8', '9'};
    std::vector<std::pair<int, std::string> > *mUnsolvedPasswords;
    tbb::concurrent_unordered_map<int, std::pair<std::string, std::string> > *mDecryptedMap;
    std::map<int, std::pair<std::string, std::string>*> *mFoundMap;
    std::unordered_map<std::string, std::string> *mHashMap;
};
