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
	PEWarrior(char* filePath);
	bool checkPE();
	int RVAToFOA(DWORD rva);
	virtual ~PEWarrior();
private:
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

		PEFileHeader() {

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

	int pESignatureAddress;
	int sizeOfImageOptionalHeader;
	DWORD currentPESignature;
	DOSPart dosPart;
	PEFileHeader peFileHeader;
	PEOptionHeader peOptionalHeader;
	SectionTables sectionTables;

	fstream* MyFile = new fstream;
	int getHex(char* address, int size);
	bool getDOSHeader();
	bool getPEFileHeader();
	bool getPEOptionHeader();
	bool getSectionHeader();
	void printTime(WORD timeStamp);
	void reverseDllCharcateristic(int position);

};