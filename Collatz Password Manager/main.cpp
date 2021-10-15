#include "PasswordManager.h"
#include <random>
#include <sstream>
#include <vector> // not using array, as it's size must be known at compile time

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

	//char* char_array = (char*)unencryptedPass.data();
	
	// any rules for password to check here? Length etc.
	int offset = 0;

	// Adding to offset then adding to string
	std::string encryptedPassword = GenerateEncryption(unencryptedPass);

	passwordFile->clear();
	*passwordFile << "" << username << " " << encryptedPassword << std::endl;
	details[username] = encryptedPassword;

	std::cout << "password is: " << encryptedPassword << std::endl;
}

void PasswordManager::CheckUsernamePassword() {
	std::string username, unencryptedPass;

	std::cout << "Please enter the new username: ";
	std::cin >> username;
	
	if (details.contains(username)) {// C++20 feature
		for (int i = 0; i < 3; ++i) {
			std::cout << "Please enter the new password: ";
			std::cin >> unencryptedPass;
			std::string encryptedPassword = GenerateEncryption(unencryptedPass);

			if (details[username] == encryptedPassword) {
				std::cout << "success!" << std::endl;
				break;
			}
			else {
				std::cout << "Failure, you have " << (2 - i) << " remaining attempts." << std::endl;
			}
		}
	}
	else {
		std::cout << "Username doesn't exist in our records" << std::endl;
	}
}

void PasswordManager::GeneratePasswordStrengthFile() {
	std::fstream passwordStrengthFile("passwordtest.txt", std::ios_base::out);

	std::random_device rd; // obtain a random number from hardware
	std::mt19937 gen(rd()); // seed the generator

	std::uniform_int_distribution<> tenLowercase(97, 122); // define the range
	std::uniform_int_distribution<> randomChar(0, 9); // define the range

	//clear file first?
	// Randomly choosing the ten characters
	char characters[10];
	for (int i = 0; i < 10; ++i) characters[i] = static_cast<int>(tenLowercase(gen)); // only choosing once, as it helps with efficiency of password generation
	
	// First 10000
	for (int i = 0; i < 10000; ++i) {
		std::vector<unsigned int> unencryptedPass;

		int passwordLength = i / 100;
		(i % 100 == 0) ? passwordLength : passwordLength++;

		for (int j = 0; j < passwordLength; ++j) {
			unencryptedPass.push_back(randomChar(gen));
		}

		passwordStrengthFile << GenerateEncryption(unencryptedPass) << std::endl;
	}

	// Second 10000
	std::uniform_int_distribution<> randomChar2(0, 255); // better way to do this?

	passwordStrengthFile << "starting second section" << std::endl;

	for (int i = 0; i < 10000; ++i) {

		bool repeatedCharacters[256] = { false }; // declare outside for loop and reset to false at end of each for?

		int passwordLength = i / 100;
		(i % 100 == 0) ? passwordLength : passwordLength++;

		std::vector<unsigned int> unencryptedPass;

		for (int j = 0; j < passwordLength; ++j) {
			int randomValue = randomChar2(gen);
			bool placed = false;
			while (!placed) {
				if (!repeatedCharacters[randomValue]) {
					unencryptedPass.push_back(randomValue);
					repeatedCharacters[randomValue] = true;
					placed = true;
				}
			}
		}
		if (unencryptedPass.size() != 0) passwordStrengthFile << GenerateEncryption(unencryptedPass) << std::endl;
	}
}

void PasswordManager::AnalysePasswordStrengthFile() {
	bool c = false;
	std::string encryption = "118114";

	/*
		Cracking idea 1:
		1. Using the size of the encyption for guidance, generate random strings
		2. Encrypt the string and see if it matches

		Cracking idea 2:
		1. take front two numbers and find a value that takes that many steps
		2. Translate that value to ascii
		3. remove the two values from encryption and repeat

		Q. First set are restricted to ten lowercase characters, how can I use this to crack the passwords?
		Q. How would I detect how many integers are a part of that character (1, 2 or 3)?


		Basis of testing:
		* Repeated characters - must be easier to crack
		* If you know they're lowercase letters (what kind of checks could you run?) - must be easier to crack
		* Having a rough idea of the length of the password (10 character encryption, so maximum 10 letter password to guess)
		* 
	*/


	while (!c) {
		std::string firstTwo = encryption.substr(0, 2);

		//int ascii = static_cast<std::string>(firstTwo);
	}
}
/*
std::vector<unsigned int> PasswordManager::StringToVector(std::string str) {
	std::vector<unsigned int> v;

	for (char& c : str) {
		v.push_back(c);
	}
}*/

std::string PasswordManager::GenerateEncryption(const std::string unencryptedPassword) {
	int offset = 0;
	std::string encryptedPassword = "";

	for (int i = 0; i < unencryptedPassword.length(); i++) {
		unsigned int ascii = ((unsigned char) unencryptedPassword[i]) + offset; // casting before addition
		int cc = CollatzConjecture(ascii);
		encryptedPassword.append(std::to_string(cc));
		offset = cc;
	}

	return encryptedPassword;
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

int PasswordManager::CollatzConjecture(int value) {
	int stepCount = 0;

	while (value != 1) {
		if (value % 2 == 0) value /= 2; //even
		else value = (value * 3) + 1; //false	
		
		stepCount++;
	}
	return stepCount;
}