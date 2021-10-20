#include "PasswordManager.h"
#include <random>
#include <sstream>
#include <vector> // not using array, as it's size must be known at compile time
#include <chrono>

int main() {
	PasswordManager pm;

	// Decrypting english sentance
	std::string englishSentance = "27322810313331033910211452912207344136146925461033281533271031012815108114101";
	//std::cout << pm.TestEncryption(englishSentance, 32, 127) << std::endl;


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
	passwordFile = std::make_unique<std::fstream>();
	stringToVectorPtr = &StringToVector;

	try {
		passwordFile->open("password.txt", std::ios_base::in | std::ios_base::app); // std::ios_base::app - seek to the end of stream before each write
	}
	catch (const std::ios_base::failure& fail) {
		std::cout << fail.what() << std::endl;
	}

	std::string line;
	while (std::getline(*passwordFile, line)) { // as long as there's another line
		std::string split = line.substr(0, line.find(' '));
		loginDetails[split] = line.substr(split.size() + 1); // + 1 here to avoid the space being associated with the encrypted password
	}
}

PasswordManager::~PasswordManager() {
	passwordFile->close();
}

void PasswordManager::CreateUsernamePassword() {
	std::string username, unencryptedPass;

	bool usernameGenerated = false;
	while (!usernameGenerated) {
		std::cout << "Please enter the new username: ";
		std::cin >> username;

		int illegalCharCount = std::count_if(username.begin(), username.end(), [](unsigned char x) { return !std::isprint(x); });

		if (username.length() == 0) {
			std::cout << "Username must be longer than 0 characters, please create another." << std::endl;
			continue;
		}
		if (!(loginDetails.find(username) == loginDetails.end())) {
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
	loginDetails[username] = encryptedPassword;
}

void PasswordManager::CheckUsernamePassword() {
	std::string username, unencryptedPass;

	std::cout << "Please enter the username: ";
	std::cin >> username;
	
	if (loginDetails.contains(username)) { // C++20 feature
		for (int i = 0; i < 3; ++i) {
			std::cout << "Please enter the password: ";
			std::cin >> unencryptedPass;
			std::string encryptedPassword = GenerateEncryption(stringToVectorPtr(unencryptedPass));

			if (loginDetails[username] == encryptedPassword) {
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
	remove("passwordtest.txt"); // removing the file ensures it's cleared before use
	std::fstream passwordStrengthFile("passwordtest.txt", std::ios_base::out);

	GeneratePasswordSet(passwordStrengthFile, true, 97, 122); // Generating first 10000
	GeneratePasswordSet(passwordStrengthFile, false, 1, 255); // Generating second 10000	
}

void PasswordManager::GeneratePasswordSet(std::fstream& passwordStrengthFile, bool repeatedCharsAllowed, int minASCII, int maxASCII) {
	int characters[10];
	bool repeatedCharacters[256] = { false };

	if (repeatedCharacters) {
		for (int i = 0; i < 10; ++i) characters[i] = minASCII + rand() % ((maxASCII + 1) - minASCII); // only choosing once, as it helps with efficiency of password generation
	}

	for (int i = 0; i < 10000; ++i) {
		std::vector<unsigned int> unencryptedPass;
		bool repeatedCharacters[256] = { false };

		int passwordLength = i / 100;
		(i % 100 == 0) ? passwordLength : passwordLength++;

		for (int j = 0; j < passwordLength; ++j) {
			int randomValue;

			if (repeatedCharsAllowed) {
				randomValue = characters[0 + rand() % ((9 + 1) - 0)];
			}
			else {
				bool placed = false;
				while (!placed) {
					randomValue = minASCII + rand() % ((maxASCII + minASCII) - minASCII); // else, generate new random value
					
					if (!repeatedCharacters[randomValue]) {
						repeatedCharacters[randomValue] = true;
						placed = true;
					}
				}
			}
			unencryptedPass.push_back(randomValue);
		}
		passwordStrengthFile << GenerateEncryption(unencryptedPass) << std::endl;
	}
}

void PasswordManager::AnalysePasswordStrengthFile() {
	std::fstream passwordStrengthFile("passwordtest.txt", std::ios_base::in);
	
	TestEncryptionHandler(97, 127, "simple", passwordStrengthFile);
	TestEncryptionHandler(1, 255, "hard", passwordStrengthFile);
}

void PasswordManager::TestEncryptionHandler(int minASCII, int maxASCII, std::string passwordType, std::fstream& passwordStrengthFile) {
	unsigned int overallTests = 0;
	unsigned int overallSuccess = 0;
	unsigned int categoryTests = 0;
	unsigned int categorySuccess = 0;
	auto overallTiming = std::chrono::high_resolution_clock::now();
	auto categoryTiming = std::chrono::high_resolution_clock::now();

	std::string line;

	for (int i = 1; i < 10000; ++i) {
		std::getline(passwordStrengthFile, line);
		overallTests++;
		categoryTests++;

		if (TestEncryption(line, 97, 127)) {
			overallSuccess++;
			categorySuccess++;
		}

		if (i % 100 == 0) { // Display success percentage after every category
			auto stop = std::chrono::high_resolution_clock::now();

			std::cout << "It took " << std::chrono::duration_cast<std::chrono::milliseconds>(stop - categoryTiming).count() << "ms to test this category of " << (i - 100) << " to "
				<< i << ' ' << passwordType << " passwords, with a success rate of " << (((double)categorySuccess / (double)categoryTests) * 100) << "% for the category." << "\n" <<
				"This means that after " << std::chrono::duration_cast<std::chrono::milliseconds>(stop - overallTiming).count() << "ms, the success rate of " << i << ' ' << passwordType
				<< " passwords is: " << (((double)overallSuccess / (double)overallTests) * 100) << "%. " << std::endl << std::endl;

			categoryTests = 0;
			categorySuccess = 0;
			categoryTiming = std::chrono::high_resolution_clock::now();
		}
	}
}

bool PasswordManager::TestEncryption(std::string encryption, int min, int max) {
	bool cracked = false;
	std::any c = min;
	std::string decrypted = "";

	while (!cracked) {
		std::string tempdecrypt;
		tempdecrypt = decrypted + (char) std::any_cast<int>(c);

		std::string tempencrypted = GenerateEncryption(StringToVector(tempdecrypt));

		if (tempencrypted == encryption.substr(0, tempencrypted.size())) {
			decrypted = tempdecrypt;
			c = 97;

			if (tempencrypted == encryption) {
				cracked = true;
			}

			continue;
		}

		if (std::any_cast<int>(c) == max) {
			if (decrypted != "") decrypted = decrypted.substr(0, decrypted.size() - 1);
			return false;
		}

		c = std::any_cast<int>(c) + 1;
	}

	return true;
}

template <typename T>
inline int CollatzConjecture(T value) {
	int stepCount = 0;

	while (value != 1) {
		if (value % 2 == 0) value /= 2; // even
		else value = (value * 3) + 1; // false	
		
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

