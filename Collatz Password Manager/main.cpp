#include <iostream>

void GenerateUsernamePassword();

int main() {

	std::cout << "1. Create username/password" << "\n" << "2. Check username and password" << "\n" << 
		"3. Generate password strength analysis file" << "\n" << "4. Analyse password strength analysis file" << std::endl;

	int input;
	std::cin >> input;

	switch (input)
	{
	case 1:
		GenerateUsernamePassword();
		break;
	default:
		std::cout << "This value isn't an option." << std::endl;
		exit(0);
		break;
	}

	return 0;
}

void GenerateUsernamePassword() {
	std::string username, unencryptedPass;

	std::cout << "Please enter the new username: ";
	std::cin >> username;

	// check if this password currently exists
	// any username rules to adhere to?

	std::cout << "Pleae enter the new password: ";
	std::cin >> unencryptedPass;

	char* char_array = &unencryptedPass[0];
	int x = sizeof(char_array);


	// any rules for password to check here? Length etc.

}