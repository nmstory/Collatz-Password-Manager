#include "PasswordManager.h"

std::vector<unsigned int> StringToVector(std::string str);

int main() {
	PasswordManager pm;

	bool running = true;

	while (running) {
		std::cout << "\n" << "1. Create username/password" << "\n" << "2. Check username and password" << "\n" << "3. Generate password strength analysis file" << 
			"\n" << "4. Analyse password strength analysis file" << "\n" << "5. Exit" << std::endl;

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
		case 5:
			running = false;
			break;
		default:
			std::cout << "This value isn't an option." << std::endl;
			break;
		}
	}
	
	return 0;
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
		std::cout << "Please enter your new username: ";
		std::cin >> username;

		int illegalCharCount = std::count_if(username.begin(), username.end(), [](unsigned char x) { return !std::isprint(x); });

		if (username.length() == 0) {
			std::cout << "Username must be longer than 0 characters, please try again." << std::endl;
			continue;
		}
		if (!(loginDetails.find(username) == loginDetails.end())) {
			std::cout << "This username already exists in our records, please try again." << std::endl;
			continue;
		}
		if (illegalCharCount == 0) {
			usernameGenerated = true;
		}
	}

	bool passwordGenerated = false;
	while (!passwordGenerated) {
		std::cout << "Please enter your new password: ";
		std::cin >> unencryptedPass;

		int illegalCharCount = std::count_if(unencryptedPass.begin(), unencryptedPass.end(), [](unsigned char x) { return !std::isprint(x); });

		if (unencryptedPass.length() == 0) {
			std::cout << "Password must be longer than 0 characters, please try again." << std::endl;
			continue;
		}
		if (illegalCharCount == 0) {
			passwordGenerated = true;
		}
	}
	
	int offset = 0;
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

	GeneratePasswordSet(passwordStrengthFile, true, 97, 122); // Generating first 10000 passwords
	GeneratePasswordSet(passwordStrengthFile, false, 1, 255); // Generating second 10000 passwords
}

void PasswordManager::AnalysePasswordStrengthFile() {
	std::fstream passwordStrengthFile("passwordtest.txt", std::ios_base::in);

	TestEncryptionHandler(97, 127, "simple", passwordStrengthFile);
	TestEncryptionHandler(1, 255, "hard", passwordStrengthFile);
}

void PasswordManager::GeneratePasswordSet(std::fstream& passwordStrengthFile, bool repeatedCharsAllowed, int minASCII, int maxASCII) {
	int characters[10];
	bool repeatedCharacters[256] = { false };

	if (repeatedCharacters) {
		for (int i = 0; i < 10; ++i) characters[i] = minASCII + rand() % ((maxASCII + 1) - minASCII);
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
					randomValue = minASCII + rand() % ((maxASCII + 1) - minASCII);
					
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

bool PasswordManager::TestEncryption(std::string encryption, int min, int max) {
	bool cracked = false;
	std::any c = min;
	std::string decrypted = "";

	while (!cracked) {
		std::string tempdecrypt;
		tempdecrypt = decrypted + (char)std::any_cast<int>(c);

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
			return false;
		}

		c = std::any_cast<int>(c) + 1;
	}

	return true;
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

		if (TestEncryption(line, minASCII, maxASCII)) {
			overallSuccess++;
			categorySuccess++;
		}

		if (i % 100 == 0) { // Display success percentage after every category
			auto stop = std::chrono::high_resolution_clock::now();
			double categroryDuration = std::chrono::duration_cast<std::chrono::milliseconds>(stop - categoryTiming).count();

			std::cout << "It took " << categroryDuration << "ms to test this category of " << (i - 100) << " to " << i << ' ' << passwordType << " passwords (" << (categroryDuration / 100) << 
				"ms per password), with a success rate of " << (((double)categorySuccess / (double)categoryTests) * 100) << "% for the category." << "\n" << "This means that after " << 
				std::chrono::duration_cast<std::chrono::milliseconds>(stop - overallTiming).count() << "ms, the success rate of " << i << ' ' << passwordType << " passwords is: " << 
				(((double)overallSuccess / (double)overallTests) * 100) << "%. " << std::endl << std::endl;

			categoryTests = 0;
			categorySuccess = 0;
			categoryTiming = std::chrono::high_resolution_clock::now();
		}
	}
}

std::vector<unsigned int> StringToVector(std::string str) {
	std::vector<unsigned int> unencryptedPassword;

	for (char& c : str) {
		unencryptedPassword.push_back(static_cast<unsigned>(static_cast<unsigned char>(c)));
	}

	return unencryptedPassword;
}