#pragma once
#include <fstream>
#include <map>
#include <iostream>
#include <string>
#include <algorithm>
#include <vector>
#include <iostream>

class PasswordManager { // inherit from collatz?
public:
	PasswordManager();
	~PasswordManager(); // virtual?

	void CreateUsernamePassword();
	void CheckUsernamePassword();
	void GeneratePasswordStrengthFile();
	void AnalysePasswordStrengthFile();
private:
	std::string GenerateEncryption(const std::vector<unsigned int>& unencryptedPassword);
	bool TestEncryption(std::string encryption, int min, int max);
	std::fstream* passwordFile;
	std::map<std::string, std::string> details; //RENAME!
};