#pragma once
#include <fstream>
#include <map>
#include <iostream>
#include <string>
#include <algorithm>
#include <vector>
#include <chrono>
#include <any>
#include <random>

template <typename T>
class Collatz {
public:
	Collatz() = default;
	~Collatz() = default;

	inline int CollatzConjecture(T value) {
		int stepCount = 0;

		while (value != 1) {
			if (value % 2 == 0) value /= 2; // even
			else value = (value * 3) + 1; // false	

			stepCount++;
		}
		return stepCount;
	}
};

class PasswordManager : public Collatz<int> {
public:
	PasswordManager();
	~PasswordManager();

	void CreateUsernamePassword();
	void CheckUsernamePassword();
	void GeneratePasswordStrengthFile();
	void AnalysePasswordStrengthFile();
private:
	bool TestEncryption(std::string encryption, int min, int max);
	void TestEncryptionHandler(int minASCII, int maxASCII, std::string passwordType, std::fstream& passwordStrengthFile);
	std::string GenerateEncryption(const std::vector<unsigned int>& unencryptedPassword);
	void GeneratePasswordSet(std::fstream& passwordStrengthFile, bool repeatedCharsAllowed, int minASCII, int maxASCII);

	std::unique_ptr<std::fstream> passwordFile;
	std::vector<unsigned int>(*stringToVectorPtr)(std::string str);
	std::map<std::string, std::string> loginDetails; // username, password
};