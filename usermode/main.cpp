#include <iostream>
#include <string_view>
#include <Windows.h>
#include <TlHelp32.h>
#include <memory>
#include <cstdint>
#include <vector>
#include "driverloader.h"
#include "injector.hpp"
#include "xor.h"
#include "skStr.h"
#include "consoleshi.hpp"
#include "auth.hpp"

std::string name = skCrypt("injector").decrypt();
std::string ownerid = skCrypt("nIBE0bnewY").decrypt();
std::string secret = skCrypt("2ad9843bb9a804f4f7517c252d062a797b15d48caeeaccce49cb1e55371fc76d").decrypt();
std::string version = skCrypt("1.0").decrypt();
std::string url = skCrypt("https://keyauth.win/api/1.2/").decrypt(); // change if you're self-hosting

int main()
{
	SetConsoleTitleA("reconnected.wtf");
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 11);
	std::string key;
	std::cout << skCrypt("\n key -> ");
	std::cin >> key;

	cout << skCrypt("\n");
	cout << skCrypt(" [+] success..\n");
	system("cls");

	// driver init
	SetConsoleTitleA("reconnected.wtf");
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 11);
	cout << skCrypt(" [+] loading driver...\n");
	BypassLoader();
	BypassLoader2();
	cout << skCrypt(" [+] driver loaded!\n");
	cout << skCrypt("\n");
	Sleep(3000);
	system("cls");
	cout << skCrypt(" ----info---- \n");

	cout << skCrypt(" [+] this is early access loader\n");
	cout << skCrypt("\n");
	cout << skCrypt(" ----reconnected.wtf----\n");
	cout << skCrypt(" [+] loading reconnected module / (waiting for game) \n");
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 7);
	face_injecor_v2(skCrypt("UnityWndClass")); // UnityWndClass -> rust
	cout << skCrypt(" \n");
	cout << skCrypt(" [+] module loaded!\n");
	raw_image.clear();

	cout << endl;
	system("pause");
}