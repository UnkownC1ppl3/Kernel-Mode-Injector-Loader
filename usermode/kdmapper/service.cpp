#include "service.hpp"

bool service::RegisterAndStart(const std::wstring& driver_path) {
	const static DWORD ServiceTypeKernel = 1;
	const std::wstring driver_name = intel_driver::GetDriverNameW();
	const std::wstring servicesPath = _xor_(L"SYSTEM\\CurrentControlSet\\Services\\").c_str() + driver_name;
	const std::wstring nPath = L"\\??\\" + driver_path;

	HKEY dservice;
	LSTATUS status = RegCreateKeyW(HKEY_LOCAL_MACHINE, servicesPath.c_str(), &dservice); //Returns Ok if already exists
	if (status != ERROR_SUCCESS) {
		Log(_xor_("[-] Can't create service key").c_str() << std::endl);
		return false;
	}

	status = RegSetKeyValueW(dservice, NULL, _xor_(L"ImagePath").c_str(), REG_EXPAND_SZ, nPath.c_str(), (DWORD)(nPath.size()*sizeof(wchar_t)));
	if (status != ERROR_SUCCESS) {
		RegCloseKey(dservice);
		Log(_xor_("[-] Can't create 'ImagePath' registry value").c_str() << std::endl);
		return false;
	}
	
	status = RegSetKeyValueW(dservice, NULL, _xor_(L"Type").c_str(), REG_DWORD, &ServiceTypeKernel, sizeof(DWORD));
	if (status != ERROR_SUCCESS) {
		RegCloseKey(dservice);
		Log(_xor_("[-] Can't create 'Type' registry value").c_str() << std::endl);
		return false;
	}
	
	RegCloseKey(dservice);

	HMODULE ntdll = GetModuleHandleA(_xor_("ntdll.dll").c_str());
	if (ntdll == NULL) {
		return false;
	}

	auto RtlAdjustPrivilege = (nt::RtlAdjustPrivilege)GetProcAddress(ntdll, _xor_("RtlAdjustPrivilege").c_str());
	auto NtLoadDriver = (nt::NtLoadDriver)GetProcAddress(ntdll, _xor_("NtLoadDriver").c_str());

	ULONG SE_LOAD_DRIVER_PRIVILEGE = 10UL;
	BOOLEAN SeLoadDriverWasEnabled;
	NTSTATUS Status = RtlAdjustPrivilege(SE_LOAD_DRIVER_PRIVILEGE, TRUE, FALSE, &SeLoadDriverWasEnabled);
	if (!NT_SUCCESS(Status)) {
		Log(_xor_("Fatal error: failed to acquire SE_LOAD_DRIVER_PRIVILEGE. Make sure you are running as administrator.").c_str() << std::endl);
		return false;
	}

	std::wstring wdriver_reg_path = _xor_(L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\").c_str() + driver_name;
	UNICODE_STRING serviceStr;
	RtlInitUnicodeString(&serviceStr, wdriver_reg_path.c_str());

	Status = NtLoadDriver(&serviceStr);
	//Log(_xor_("[+] NtLoadDriver Status 0x").c_str() << std::hex << Status << std::endl);
	
	//Never should occur since kdmapper checks for "IsRunning" driver before
	if (Status == 0xC000010E) {// STATUS_IMAGE_ALREADY_LOADED
		return true;
	}
	
	return NT_SUCCESS(Status);
}

bool service::StopAndRemove(const std::wstring& driver_name) {
	HMODULE ntdll = GetModuleHandleA(_xor_("ntdll.dll").c_str());
	if (ntdll == NULL)
		return false;

	std::wstring wdriver_reg_path = _xor_(L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\").c_str() + driver_name;
	UNICODE_STRING serviceStr;
	RtlInitUnicodeString(&serviceStr, wdriver_reg_path.c_str());

	HKEY driver_service;
	std::wstring servicesPath = _xor_(L"SYSTEM\\CurrentControlSet\\Services\\").c_str() + driver_name;
	LSTATUS status = RegOpenKeyW(HKEY_LOCAL_MACHINE, servicesPath.c_str(), &driver_service);
	if (status != ERROR_SUCCESS) {
		if (status == ERROR_FILE_NOT_FOUND) {
			return true;
		}
		return false;
	}
	RegCloseKey(driver_service);

	auto NtUnloadDriver = (nt::NtUnloadDriver)GetProcAddress(ntdll, _xor_("NtUnloadDriver").c_str());
	NTSTATUS st = NtUnloadDriver(&serviceStr);
	//Log(_xor_("[+] NtUnloadDriver Status 0x").c_str() << std::hex << st << std::endl);
	if (st != 0x0) {
		Log(_xor_("[-] Driver Unload Failed!!").c_str() << std::endl);
		status = RegDeleteKeyW(HKEY_LOCAL_MACHINE, servicesPath.c_str());
		return false; //lets consider unload fail as error because can cause problems with anti cheats later
	}
	

	status = RegDeleteKeyW(HKEY_LOCAL_MACHINE, servicesPath.c_str());
	if (status != ERROR_SUCCESS) {
		return false;
	}
	return true;
}
