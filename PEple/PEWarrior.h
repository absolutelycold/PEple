// Author: Absolutelycold
// https://github.com/absolutelycold
// Date: 03/08/2020

#pragma once
#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <fstream>
#include <math.h>
#include <windows.h> // WORD, DWORD, BYTE type
#include <winnt.h> // PE STRUCTURE
#include <bitset>
using namespace std;

class PEWarrior
{

public:
	class DOSPart
	{
	public:
		static const int sizeOfDosHeader = 64; //40h
		static const int PositionOfPESignatureAddress = 60; // 40h - 4, the last member in DOS header
		static const int PositionOfMZSignature = 0; // the first memeber is MZ signature
		static const WORD Signature = 23117; // MZ

		WORD MZSignature;
		DWORD positionOfPESignature;

		DOSPart() {

		}
	private:

	};

	class PEFileHeader
	{

	public:
		const int sizeOfFileHeader = 0x14; //14h
		WORD machine; // What kind of CPU can run the EXE
		WORD numberOfSection;
		WORD timeStamp;
		WORD sizeOfOptionalHeader;
		WORD characteristics;
		_IMAGE_FILE_HEADER* header;

		PEFileHeader() {

		}
		~PEFileHeader() {
			delete[] header;
		}
	private:

	};

	class PEOptionHeader
	{
	public:
		WORD magic;
		DWORD addressOfEntryPoint;
		DWORD baseAddress;
		DWORD fileAlignment;
		DWORD memoryAlignment;
		DWORD sizeOfImage;
		DWORD sizeOfHeaders;
		DWORD checkSum;
		DWORD dllCharacteristic;
		PEOptionHeader() {

		}
		~PEOptionHeader() {
			delete[] peOptionalHeader;
		}
		void setHeader(void* headerAddress);
		void* getHeaeder();

	private:
		void* peOptionalHeader;
	};

	class SectionTables
	{
	public:

		_IMAGE_SECTION_HEADER* tableArray;
		int numberOfSections;
		SectionTables() {

		}
		~SectionTables();

		void setArrayStartAddress(_IMAGE_SECTION_HEADER* tablesAddress);
		void setNumberOfSections(int num);
	private:

	};

	class ExportDirectory
	{
	public:
		_IMAGE_EXPORT_DIRECTORY* Directory;
		DWORD RVAOfDllName;
		DWORD RVAOfFAT;
		DWORD RVAOfFNT;
		DWORD RVAOfFOT;
		DWORD Base;
		DWORD NumberOfFunctions;
		DWORD NumberOfNames;
		DWORD* FNT;
		WORD* FOT;
		DWORD* FAT;
		bool exist;

		~ExportDirectory();

	private:

	};

	class RelocateDirectory
	{
	public:
		DWORD VirtualAddress;
		DWORD numberOfPage = 0;
		bool exist;
	private:

	};

	class ImportDirectory
	{
	public:
		DWORD entryOfImportDirectory;

	private:

	};

	DWORD currentPESignature;
	DOSPart dosPart;
	PEFileHeader peFileHeader;
	PEOptionHeader peOptionalHeader;
	SectionTables sectionTables;
	ExportDirectory exportDirectory;
	RelocateDirectory relocateDirectory;
	ImportDirectory importDirectory;
	

	PEWarrior(char* filePath);
	bool checkPE();
	int RVAToFOA(DWORD rva);
	DWORD FOAToRVA(DWORD foa);
	void injectMessageBoxA32(DWORD funAddress);
	void injectMessageBoxA32AtEnd(DWORD funAddress);
	void modifyEntryPoint(DWORD newEntryPoint);
	void setDllCharcateristic(int position, int value);
	void setSectionCharacteristic(int indexOfTable, int indeOfBit, int value);
	void extendLastSection(int size);
	void addASection(DWORD size);
	void combineSectonToOne();
	void inject32(DWORD startFOA, BYTE* shellcode, DWORD length);
	void reloadFile();
	void bakFile();
	DWORD getExportFunctionAddressByName(char* name);
	DWORD getExportFunctionAddressByOrdinal(DWORD ordinal);
	void moveExportTablesToNewSection();
	void moveRelocationTablesToNewSection();
	void changeImageBase32(DWORD newImageBase);
	void getImportDirectory();
	void injectDll32(char* dllName);

	virtual ~PEWarrior();
private:
	char filepath[1024];
	int pESignatureAddress;
	int sizeOfImageOptionalHeader;
	

	fstream* MyFile = new fstream;
	int getHex(char* address, int size);
	bool getDOSHeader();
	bool getPEFileHeader();
	bool getPEOptionHeader();
	bool getSectionHeader();
	bool getExportDirectory();
	bool getRelocateTable();
	void printTime(WORD timeStamp);
	
	DWORD findInjectableSection(int size);

};