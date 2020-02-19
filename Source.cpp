#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <gpedit.h>
#include <string>
#include <iostream>
#include <fstream>
#include <vector>
#include <stdio.h>


int setRestriction(const char* number, const BYTE* executableName) //1 , (BYTE*)"notepad.exe";
{
	IGroupPolicyObject* pGPO = NULL;
	const IID my_IID_IGroupPolicyObject =
	{ 0xea502723, 0xa23d, 0x11d1, {0xa7, 0xd3, 0x0, 0x0, 0xf8, 0x75, 0x71, 0xe3} };
	const IID my_CLSID_GroupPolicyObject =
	{ 0xea502722, 0xa23d, 0x11d1, {0xa7, 0xd3, 0x0, 0x0, 0xf8, 0x75, 0x71, 0xe3} };
	GUID snap_guid =
	{ 0x3d271cfc, 0x2bc6, 0x4ac2, {0xb6, 0x33, 0x3b, 0xdf, 0xf5, 0xbd, 0xab, 0x2a} };
	GUID ext_guid = REGISTRY_EXTENSION_GUID;

	LPCTSTR subKeyExplorer = L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer";
	LPCTSTR subKeyDisallowRun = L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\DisallowRun";
	LPCTSTR valueName = L"DisallowRun";

	HKEY ghKey, ghSubKey, hSubKey;
	DWORD dwkeyValue = 1;

	CoInitialize(NULL);

	HRESULT hr = CoCreateInstance(my_CLSID_GroupPolicyObject, NULL, CLSCTX_ALL, my_IID_IGroupPolicyObject, (LPVOID*)& pGPO);
	if (!SUCCEEDED(hr))
	{
		std::cout << "Failed to initialize GPO" << std::endl;
		return 1;
	}

	if (RegCreateKeyEx(HKEY_CURRENT_USER, subKeyExplorer, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hSubKey, NULL))
	{
		std::cout << "Failed to create Policies\\Explorer registry key" << std::endl;
		CoUninitialize();
		return 1;
	}

	if (RegSetValueEx(hSubKey, valueName, 0, REG_DWORD, (BYTE*) &(dwkeyValue), sizeof(dwkeyValue)))
	{
		std::cout << "Failed to set registry key" << std::endl;
		RegCloseKey(hSubKey);
		CoUninitialize();
		return 1;
	}

	if (RegCreateKeyEx(HKEY_CURRENT_USER, subKeyDisallowRun, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hSubKey, NULL))
	{
		std::cout << "Failed to create Policies\\Explorer\\DisallowRun registry key" << std::endl;
		CoUninitialize();
		return 1;
	}

	if (RegSetValueExA(hSubKey, number, 0, REG_SZ, executableName, 11))
	{
		std::cout << "Failed to set registry key" << std::endl;
		RegCloseKey(hSubKey);
		CoUninitialize();
		return 1;
	}

	if (pGPO->OpenLocalMachineGPO(GPO_OPEN_LOAD_REGISTRY))
	{
		std::cout << "Failed to get the GPO mapping" << std::endl;
		CoUninitialize();
		return 1;
	}

	if (pGPO->GetRegistryKey(GPO_SECTION_USER, &ghKey))
	{
		std::cout << "Failed to get the GPO_SECTION_USER key" << std::endl;
		CoUninitialize();
		return 1;
	}

	if (RegCreateKeyEx(ghKey, subKeyExplorer, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &ghSubKey, NULL))
	{
		std::cout << "Cannot create \\Explorer\\ key (GPO)" << std::endl;
		RegCloseKey(ghKey);
		CoUninitialize();
		return 1;
	}

	if (RegSetValueEx(ghSubKey, valueName, 0, REG_DWORD, (BYTE*)& dwkeyValue, sizeof(dwkeyValue)))
	{
		std::cout << "Cannot set \\Explorer\\ value (GPO)" << std::endl;
		RegCloseKey(ghKey);
		RegCloseKey(ghSubKey);
		CoUninitialize();
		return 1;
	}

	if (RegCreateKeyEx(ghKey, subKeyDisallowRun, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &ghSubKey, NULL))
	{
		std::cout << "Cannot create \\DisallowRun\\ key (GPO)" << std::endl;
		RegCloseKey(ghKey);
		CoUninitialize();
		return 1;
	}

	if (RegSetValueExA(ghSubKey, number, 0, REG_SZ, executableName, 11))
	{
		std::cout << "Failed to set \\DisallowRun\\ registry key (GPO)" << std::endl;
		RegCloseKey(hSubKey);
		CoUninitialize();
		return 1;
	}

	if (pGPO->Save(false, true, &ext_guid, const_cast<GUID*>(&snap_guid)))
	{
		std::cout << "GPO save failed" << std::endl;
		RegCloseKey(ghKey);
		RegCloseKey(ghSubKey);
		CoUninitialize();
		return 1;
	}

	pGPO->Release();
	RegCloseKey(ghKey);
	RegCloseKey(ghSubKey);
	CoUninitialize();
	std::cout << executableName << " restricted successfully" << std::endl;
	return 0;
}


int main()
{
	std::ifstream file("C:\\conf.txt");

	if (!file.is_open())
		return 1; 

	std::string str;
	std::vector<std::string> lines; 

	while (std::getline(file, str))           
		lines.push_back(str);
	
	file.close();

	for (int i = 0; i < lines.size(); i++)
	{
		std::vector<char> bytes(lines[i].begin(), lines[i].end());
		bytes.push_back('\0');
		char* exeName = &bytes[0];
		setRestriction(std::to_string(i + 1).c_str(), (BYTE*)exeName);
	}
		

	return 0;
}