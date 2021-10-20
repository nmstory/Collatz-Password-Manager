#pragma once
#include <fstream>
#include <map>
#include <iostream>
#include <string>
#include <algorithm>
#include <vector>
#include <iostream>
#include <chrono>
#include <any>

class PasswordManager { // inherit from collatz?
public:
	PasswordManager();
	~PasswordManager(); // virtual?

	void CreateUsernamePassword();
	void CheckUsernamePassword();
	void GeneratePasswordStrengthFile();
	void AnalysePasswordStrengthFile();
private:
	bool TestEncryption(std::string encryption, int min, int max);
	void GeneratePasswordSet(std::fstream& passwordStrengthFile, bool repeatedCharsAllowed, int minASCII, int maxASCII);
	void TestEncryptionHandler(int minASCII, int maxASCII, std::string passwordType, std::fstream& passwordStrengthFile);
	std::string GenerateEncryption(const std::vector<unsigned int>& unencryptedPassword);
	std::unique_ptr<std::fstream> passwordFile;
	std::vector<unsigned int>(*stringToVectorPtr)(std::string str);
	std::map<std::string, std::string> loginDetails; // username, password
};