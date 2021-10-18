#pragma once
#include <fstream>
#include <map>
#include <iostream>
#include <string>
#include <algorithm>
#include <vector>
#include <iostream>

struct Password {
	std::string pw;

	Password() : pw{ "" } {}
	Password(const std::string& x) : pw{ x } {}
	Password(std::string&& x) : pw{ x } {}
	Password& operator=(const std::string& x) { pw = x; return *this; }
	Password& operator=(std::string&& x)  { pw = x; return *this;  }
	Password(const Password& x) = default;
	Password(Password&& x) = default;
	Password& operator=(const Password& x) = default;
	Password& operator=(Password&& x) = default;

	friend std::ostream& operator<<(std::ostream& os, const Password& dt) {
		return os << dt.pw;
	}
	friend std::istream& operator>>(std::istream& os, Password& dt) {
		return os >> dt.pw;
	}
	operator std::string() const {
		return pw;
	}
	operator std::vector<unsigned int>() const {
		std::vector<unsigned int> v;

		for (char c : pw) {
			v.push_back(c);
		}
		return v;
	}
	char operator[](int i) const {
		return pw.at(i);
	}


};


class PasswordManager { // inherit from collatz?
public:
	PasswordManager();
	~PasswordManager(); // virtual?

	void CreateUsernamePassword();
	void CheckUsernamePassword();
	void GeneratePasswordStrengthFile();
	void AnalysePasswordStrengthFile();

	int CollatzConjecture(int value);
private:
	std::string GenerateEncryption(const std::vector<unsigned int>& unencryptedPassword);
	bool TestEncryption(std::string encryption, int min, int max);
	std::vector<unsigned int> StringToVector(std::string str); // Change this from relying on a function to a custom cast/friend function?
	std::fstream* passwordFile;
	std::map<std::string, std::string> details; //RENAME!


};