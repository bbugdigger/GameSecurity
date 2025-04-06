#pragma once

#include <functional>

#include "Undefined.h"
#include "CRC.h"

using namespace UndefinedNt;

#define CALLBACK_TYPE void()

class IntegrityChecker {
public:
	enum Section {
		UNKNOWN, TEXT, DATA, TLS, RSRC, RDATA
	};
	enum Type {
		SELF, REMOTE
	};
private:
	Type CheckType;
	Section PeSection;
	uintptr_t SectionStart;
	size_t SectionSize;

	std::uint32_t SectionCrc;

	std::function<CALLBACK_TYPE> Callback;
private:
	void CalculateModuleHash(uintptr_t base) {
		if (!base)
			return;

		auto pDosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
		auto pNtHeader = reinterpret_cast<IMAGE_NT_HEADERS64*>(base + pDosHeader->e_lfanew);
		auto pSectionHeaders = reinterpret_cast<IMAGE_SECTION_HEADER*>((uintptr_t)&pNtHeader->OptionalHeader + pNtHeader->FileHeader.SizeOfOptionalHeader);

		for (int i = 0; i < pNtHeader->FileHeader.NumberOfSections - 1; i++)
		{
			if (_stricmp(reinterpret_cast<const char*>(pSectionHeaders[i].Name), ".text"))
			{
				auto pTextSectionHeader = pSectionHeaders + i;
				auto textSectionStart = (base + pTextSectionHeader->VirtualAddress);
				SectionStart = textSectionStart;

				auto extraSpace = (0x1000 - (static_cast<uintptr_t>(pTextSectionHeader->Misc.VirtualSize) % 0x1000)) % 0x1000;
				if (pTextSectionHeader->Misc.VirtualSize && pTextSectionHeader->Misc.VirtualSize > pTextSectionHeader->SizeOfRawData)
					SectionSize = pTextSectionHeader->Misc.VirtualSize + extraSpace;
				else
					SectionSize = pTextSectionHeader->SizeOfRawData + extraSpace;

				break;
			}
		}
		SectionCrc = CRC::Calculate(reinterpret_cast<void*>(SectionStart), SectionSize, CRC::CRC_32());
	}
public:
	IntegrityChecker(Type checkType = SELF, Section section, std::function<CALLBACK_TYPE> callback, wchar_t* targetDll = nullptr, uintptr_t moduleBase) 
		: CheckType(checkType), PeSection(section), Callback(std::move(callback)) {
		if (checkType == Type::SELF) {
			SelfIntegrityCheck(targetDll);
		}
		else {
			// we should probably read a file from the disk and memory and then compare if we are integrity checking for remote process!
			CalculateModuleHash(moduleBase);
		}
	}

	void SelfIntegrityCheck(wchar_t* targetDll) {
		unsigned long long pPeb = __readgsqword(PEBOffset);

		pPeb = *reinterpret_cast<decltype(pPeb)*>(pPeb + LdrOffset);
		PLDR_DATA_TABLE_ENTRY pModuleList = *reinterpret_cast<PLDR_DATA_TABLE_ENTRY*>(pPeb + ListOffset);
		while (pModuleList->DllBase)
		{
			if (_wcsicmp(pModuleList->BaseDllName.Buffer, targetDll))
				CalculateModuleHash((uintptr_t)pModuleList->DllBase);

			pModuleList = reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(pModuleList->InLoadOrderLinks.Flink);
		}
	}

	bool CheckSection() {
		if (!SectionSize) return false;

		const auto current = CRC::Calculate(reinterpret_cast<void*>(SectionStart), SectionSize, CRC::CRC_32());
		
		if (SectionCrc != current) {
			Callback();
		}
	}
};