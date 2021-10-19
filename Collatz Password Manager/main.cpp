#include "PasswordManager.h"
#include <random>
#include <sstream>
#include <vector> // not using array, as it's size must be known at compile time
#include <chrono>

int main() {
	PasswordManager pm;

	std::cout << "1. Create username/password" << "\n" << "2. Check username and password" << "\n" << 
		"3. Generate password strength analysis file" << "\n" << "4. Analyse password strength analysis file" << std::endl;

	int input;
	std::cin >> input;

	switch (input)
	{
	case 1:
		pm.CreateUsernamePassword();
		break;
	case 2:
		pm.CheckUsernamePassword();
		break;
	case 3:
		pm.GeneratePasswordStrengthFile();
		break;
	case 4:
		pm.AnalysePasswordStrengthFile();
		break;
	default:
		std::cout << "This value isn't an option." << std::endl;
		exit(0);
		break;
	}
	
	return 0;
}


std::vector<unsigned int> StringToVector(std::string str) {
	std::vector<unsigned int> unencryptedPassword;

	for (char& c : str) {
		unencryptedPassword.push_back(std::char_traits<char>().to_int_type(c));
	}

	return unencryptedPassword;
}

PasswordManager::PasswordManager() {
	passwordFile = new std::fstream;

	try {
		passwordFile->open("password.txt", std::ios_base::in | std::ios_base::app); // std::ios_base::app - seek to the end of stream before each write
	}
	catch (const std::ios_base::failure& fail) {
		std::cout << fail.what() << std::endl;
	}

	std::string line;
	while (std::getline(*passwordFile, line)) { // as long as there's another line
		std::string split = line.substr(0, line.find(' '));
		details[split] = line.substr(split.size() + 1); // + 1 here to avoid the space being associated with the encrypted password
	}
}

PasswordManager::~PasswordManager() {
	passwordFile->close();
	delete passwordFile;
	passwordFile = nullptr;
}

void PasswordManager::CreateUsernamePassword() {
	std::string username, unencryptedPass;

	std::vector<unsigned int> (*stringToVectorPtr)(std::string str);
	stringToVectorPtr = &StringToVector;

	bool usernameGenerated = false;
	while (!usernameGenerated) {
		std::cout << "Please enter the new username: ";
		std::cin >> username;

		int illegalCharCount = std::count_if(username.begin(), username.end(), [](unsigned char x) { return !std::isprint(x); }); // allow spaces?

		if (username.length() == 0) {
			std::cout << "Username must be longer than 0 characters, please create another." << std::endl;
			continue;
		}
		if (!(details.find(username) == details.end())) { // Username already exists
			std::cout << "This username already exists in our records, please use another." << std::endl;
			continue;
		}
		if (illegalCharCount == 0) {
			usernameGenerated = true;
		}
	}
	std::cout << "Please enter the new password: ";
	std::cin >> unencryptedPass;
	
	// any rules for password to check here? Length etc.
	int offset = 0;

	// Adding to offset then adding to string
	std::string encryptedPassword = GenerateEncryption(stringToVectorPtr(unencryptedPass));

	passwordFile->clear();
	*passwordFile << "" << username << " " << encryptedPassword << std::endl;
	details[username] = encryptedPassword;

	std::cout << "password is: " << encryptedPassword << std::endl;
}

void PasswordManager::CheckUsernamePassword() {
	std::string username, unencryptedPass;

	std::cout << "Please enter the new username: ";
	std::cin >> username;

	std::vector<unsigned int>(*stringToVectorPtr)(std::string str);
	stringToVectorPtr = &StringToVector;

	
	if (details.contains(username)) {// C++20 feature
		for (int i = 0; i < 3; ++i) {
			std::cout << "Please enter the new password: ";
			std::cin >> unencryptedPass;
			std::string encryptedPassword = GenerateEncryption(stringToVectorPtr(unencryptedPass));

			if (details[username] == encryptedPassword) {
				std::cout << "Success!" << std::endl;
				break;
			}
			else {
				std::cout << "Failure! You have " << (2 - i) << " remaining attempts." << std::endl;
			}
		}
	}
	else {
		std::cout << "Username doesn't exist in our records" << std::endl;
	}
}

void PasswordManager::GeneratePasswordStrengthFile() {
	std::fstream passwordStrengthFile("passwordtest.txt", std::ios_base::out);

	//clear file first?

	// Randomly choosing the ten characters
	int characters[10];
	//for (int i = 0; i < 10; ++i) characters[i] = (rand() % (122 + 97)); // only choosing once, as it helps with efficiency of password generation
	for (int i = 0; i < 10; ++i) characters[i] = 97 + rand() % ((122 + 1) - 97); // only choosing once, as it helps with efficiency of password generation
	
	// First 10000
	for (int i = 0; i < 10000; ++i) {
		std::vector<unsigned int> unencryptedPass;

		int passwordLength = i / 100;
		(i % 100 == 0) ? passwordLength : passwordLength++;

		for (int j = 0; j < passwordLength; ++j) {
			//unencryptedPass.push_back(characters[rand() % 9 + 0]);
			unencryptedPass.push_back(characters[0 + rand() % ((9 + 1) - 0)]);
		}

		passwordStrengthFile << GenerateEncryption(unencryptedPass) << std::endl;
	}

	// Second 10000
	for (int i = 0; i < 10000; ++i) {
		bool repeatedCharacters[256] = { false };

		int passwordLength = i / 100;
		(i % 100 == 0) ? passwordLength : passwordLength++;

		std::vector<unsigned int> unencryptedPass;

		for (int j = 0; j < passwordLength; ++j) {
			//int randomValue = rand() % 255 + 1; // not 0, breaks collatz
			int randomValue = 1 + rand() % ((255 + 1) - 1); // not 0, breaks collatz
			bool placed = false;
			while (!placed) {
				if (!repeatedCharacters[randomValue]) {
					unencryptedPass.push_back(randomValue);
					repeatedCharacters[randomValue] = true;
					placed = true;
				}
				else {
					//randomValue = rand() % 255 + 1; // else, generate new random value
					randomValue = 1 + rand() % ((255 + 1) - 1); // else, generate new random value
				}
			}
		}
		if (unencryptedPass.size() != 0) passwordStrengthFile << GenerateEncryption(unencryptedPass) << std::endl;
	}
}

void PasswordManager::AnalysePasswordStrengthFile() {
	std::fstream passwordStrengthFile("passwordtest.txt", std::ios_base::in);
	unsigned int tests = 0;
	unsigned int success = 0;

	auto start = std::chrono::high_resolution_clock::now();

	std::string line;

	for (int i = 0; i < 10000; ++i) {
		std::getline(passwordStrengthFile, line);
		tests++;

		if (TestEncryption(line, 97, 127)) success++;

		if (i % 100 == 0) {
			auto stop = std::chrono::high_resolution_clock::now();
			std::cout << "After " << std::chrono::duration_cast<std::chrono::milliseconds>(stop - start).count() << "ms, the success rate of " << i << 
				" simple passwords is: " << (((double)success / (double)tests) * 100) << "%" << std::endl;
		}
	}

	start = std::chrono::high_resolution_clock::now();

	for (int i = 0; i < 10000; ++i) {
		std::getline(passwordStrengthFile, line);
		tests++;

		if (TestEncryption(line, 1, 255)) success++;

		if (i % 100 == 0) {
			auto stop = std::chrono::high_resolution_clock::now();
			std::cout << "After " << std::chrono::duration_cast<std::chrono::milliseconds>(stop - start).count() << "ms, the success rate of " << i << 
				" hard passwords is: " << (((double)success / (double)tests) * 100) << "%" << std::endl;
		}
	}
}

bool PasswordManager::TestEncryption(std::string encryption, int min, int max) {
	bool cracked = false;
	unsigned int c = min;
	std::string decrypted = "";

	while (!cracked) {
		std::string tempdecrypt = decrypted + ((char)c);
		std::string tempencrypted = GenerateEncryption(StringToVector(tempdecrypt));

		if (tempencrypted == encryption.substr(0, tempencrypted.size())) {
			decrypted = tempdecrypt;
			c = 97;

			if (tempencrypted == encryption) {
				cracked = true;
			}

			continue;
		}

		if (c == max) {
			if (decrypted != "") decrypted = decrypted.substr(0, decrypted.size() - 1);
			return false;
		}

		++c;
	}

	return true;
}

int CollatzConjecture(int value) {
	int stepCount = 0;

	while (value != 1) {
		if (value % 2 == 0) value /= 2; //even
		else value = (value * 3) + 1; //false	
		
		stepCount++;
	}
	return stepCount;
}

std::string PasswordManager::GenerateEncryption(const std::vector<unsigned int>& unencryptedPassword) {
	int offset = 0;
	std::string encryptedPassword = "";

	for (int i = 0; i < unencryptedPassword.size(); i++) {
		unsigned int ascii = unencryptedPassword[i] + offset;
		int cc = CollatzConjecture(ascii);
		encryptedPassword.append(std::to_string(cc));
		offset = cc;
	}

	return encryptedPassword;
}

