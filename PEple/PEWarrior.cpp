#include "PEWarrior.h"
#include <time.h>

PEWarrior::PEWarrior(char* filePath)
{
	this->MyFile->open(filePath, ios::binary | ios::in | ios::out);
	if (!this->MyFile->is_open())
	{
		cout << "Cannot open the file.\n";
	}
	else
	{
		cout << "DOS PART----------------------------------------------------" << endl;
		getDOSHeader();
		cout << "------------------------------------------------------------\n" << endl;
		cout << "PE FILE HEADER PART-----------------------------------------" << endl;
		getPEFileHeader();
		cout << "------------------------------------------------------------\n" << endl;
		cout << "PE OPTIONAL HEADER PART ------------------------------------" << endl;
		getPEOptionHeader();
		cout << "------------------------------------------------------------\n" << endl;
		getSectionHeader();
		reverseDllCharcateristic(6);

		//DWORD FOA = RVAToFOA(0x00404018);
		//cout << "FOA: " << hex << FOA << endl;
	}
}


bool PEWarrior::checkPE()
{
	
	if (!this->MyFile->is_open())
	{
		cout << "The file is nnot open yet";
		return false;
	}
	// copy 2048 bytes to buffer
	char* binaryBuffer = new char[2048];
	this->MyFile->read(binaryBuffer, 2048);

	//First 2 bytes are MZ significant
	char MZHeader[3];
	strncpy(MZHeader, binaryBuffer, 2);
	MZHeader[2] = '\0';
	int isMZ = strcmp(MZHeader, "MZ");
	if (isMZ == 0)
	{
		cout << "this is MZ file\n";
	}

	// The Position of PE Symbol is in the 60 bytes of the file
	char PESybolPosition[1];

	//Check if the file is PE file, 3Ch = 60
	strncpy(PESybolPosition, binaryBuffer + 60, 1);
	/*printf("%d \n", (unsigned char)PESybolPosition[0]);*/
	char PESymbol[3];
	strncpy(PESymbol, binaryBuffer + (unsigned char)PESybolPosition[0], 2);
	PESymbol[2] = '\0';
	int isPE = strcmp(PESymbol, "PE");
	if (isPE == 0)
	{
		cout << "this is PE file\n";
	}

	// Give the PE Symboal Address to class member.
	this->pESignatureAddress = (unsigned char)PESybolPosition[0];

	//cout << PESymbol << endl;

	delete[] binaryBuffer;

	if (isMZ && isPE)
	{
		return true;
	}
	else
	{
		return false;
	}
	
}

int PEWarrior::RVAToFOA(DWORD rva)
{
	DWORD rvaOffsetBase = rva - peOptionalHeader.baseAddress;
	//If RVA in the header reagion, just return it.
	if (rvaOffsetBase < peOptionalHeader.sizeOfHeaders)
	{
		return rvaOffsetBase;
	}
	
	// check whether RVA is in the each section
	for (int i = 0; i < sectionTables.numberOfSections; i++)
	{
		DWORD currentSectionSize;
		// get the bigger size between file size and memory size.
		if (sectionTables.tableArray[i].Misc.VirtualSize > sectionTables.tableArray[i].SizeOfRawData)
		{
			currentSectionSize = sectionTables.tableArray[i].Misc.VirtualSize;
		}
		else {
			currentSectionSize = sectionTables.tableArray[i].SizeOfRawData;
		}

		// Check whether the RVAOffsetBase is in the section
		if ((rvaOffsetBase >= sectionTables.tableArray[i].VirtualAddress) && (rvaOffsetBase < (sectionTables.tableArray[i].VirtualAddress + currentSectionSize)))
		{
			
			DWORD sectionOffset = rvaOffsetBase - sectionTables.tableArray[i].VirtualAddress;
			DWORD FOA = sectionTables.tableArray[i].PointerToRawData + sectionOffset;
			return FOA;
		}
	}

	return -1;
}

PEWarrior::~PEWarrior()
{
	delete MyFile;
}

int PEWarrior::getHex(char* address, int size)
{
	int hex = 0;
	for (int i = 0; i < size; i++)
	{
		hex += (address[i] * pow(16, size - 1 - i));
	}
	return hex;
}

bool PEWarrior::getDOSHeader()
{
	if (!this->MyFile->is_open())
	{
		cout << "Please load a file first.\n";
		return false;
	}
	
	char* DOSHeaderBuffer = new char[dosPart.sizeOfDosHeader];
	MyFile->read(DOSHeaderBuffer, dosPart.sizeOfDosHeader);

	// MZ signature
	dosPart.MZSignature = ((_IMAGE_DOS_HEADER*)DOSHeaderBuffer)->e_magic; 
	// PE signature position
	dosPart.positionOfPESignature = ((_IMAGE_DOS_HEADER*)DOSHeaderBuffer)->e_lfanew;
	cout << "MZ signature: " << hex << ((char*)(&(dosPart.MZSignature)))[0] << ((char*)(&(dosPart.MZSignature)))[1] << endl;
	cout << "PE signature position: " << hex << dosPart.positionOfPESignature << endl;
	delete[] DOSHeaderBuffer;
	return true;
}

bool PEWarrior::getPEFileHeader()
{
	if (dosPart.MZSignature != dosPart.Signature)
	{
		return false;
	}
	
	char* PEFileHeaderBuffer = new char[peFileHeader.sizeOfFileHeader];
	
	
	MyFile->seekg(dosPart.positionOfPESignature);
	// The first 4 Bytes is PE signature
	MyFile->read((char*)&currentPESignature, sizeof(DWORD));
	cout << "PE signature: " << ((char*)(&currentPESignature))[0] << ((char*)(&currentPESignature))[1] << endl;
	MyFile->read(PEFileHeaderBuffer, peFileHeader.sizeOfFileHeader);
	peFileHeader.sizeOfOptionalHeader = ((_IMAGE_FILE_HEADER*)PEFileHeaderBuffer)->SizeOfOptionalHeader;
	peFileHeader.machine = ((_IMAGE_FILE_HEADER*)PEFileHeaderBuffer)->Machine;
	cout << "Size Of Optional Header: " << hex << peFileHeader.sizeOfOptionalHeader << endl;
	if (peFileHeader.machine == 0)
	{
		cout << "This exe run in: Every CPU" << endl;
	}
	else if (peFileHeader.machine == 0x14c) {
		cout << "This exe run in: 32 bit computer" << endl;
	}
	else if (peFileHeader.machine == 0x8664) {
		cout << "This exe run in: 64 bit computer" << endl;
	}
	else {
		cout << "This exe run in: other CPU" << endl;
	}

	peFileHeader.numberOfSection = ((_IMAGE_FILE_HEADER*)PEFileHeaderBuffer)->NumberOfSections;
	cout << "Sections: " << peFileHeader.numberOfSection << endl;
	peFileHeader.timeStamp = ((_IMAGE_FILE_HEADER*)PEFileHeaderBuffer)->TimeDateStamp;
	peFileHeader.characteristics = ((_IMAGE_FILE_HEADER*)PEFileHeaderBuffer)->Characteristics;
	delete[] PEFileHeaderBuffer;
	return true;
}

bool PEWarrior::getPEOptionHeader()
{
	if (!MyFile->is_open())
	{
		return false;
	}
	
	char* PEoptionalHeaderBuffer = new char[peFileHeader.sizeOfOptionalHeader];
	MyFile->seekg(dosPart.positionOfPESignature + 4 + 20);
	MyFile->read(PEoptionalHeaderBuffer, peFileHeader.sizeOfOptionalHeader);
	peOptionalHeader.setHeader(PEoptionalHeaderBuffer);
	//Firstly, we nned to figure out if the exe 64 bit or 32 bit
	
	if (peFileHeader.machine == 0x14c)
	{
		peOptionalHeader.magic = ((_IMAGE_OPTIONAL_HEADER*)PEoptionalHeaderBuffer)->Magic;
		peOptionalHeader.baseAddress = ((_IMAGE_OPTIONAL_HEADER*)PEoptionalHeaderBuffer)->ImageBase;
		peOptionalHeader.addressOfEntryPoint = ((_IMAGE_OPTIONAL_HEADER*)PEoptionalHeaderBuffer)->AddressOfEntryPoint;
		peOptionalHeader.fileAlignment = ((_IMAGE_OPTIONAL_HEADER*)PEoptionalHeaderBuffer)->FileAlignment;
		peOptionalHeader.memoryAlignment = ((_IMAGE_OPTIONAL_HEADER*)PEoptionalHeaderBuffer)->SectionAlignment;
		peOptionalHeader.sizeOfImage = ((_IMAGE_OPTIONAL_HEADER*)PEoptionalHeaderBuffer)->SizeOfImage;
		peOptionalHeader.sizeOfHeaders = ((_IMAGE_OPTIONAL_HEADER*)PEoptionalHeaderBuffer)->SizeOfHeaders;
		peOptionalHeader.checkSum = ((_IMAGE_OPTIONAL_HEADER*)PEoptionalHeaderBuffer)->CheckSum;
		peOptionalHeader.dllCharacteristic = ((_IMAGE_OPTIONAL_HEADER*)PEoptionalHeaderBuffer)->DllCharacteristics;
	}
	else {
		peOptionalHeader.magic = ((_IMAGE_OPTIONAL_HEADER64*)PEoptionalHeaderBuffer)->Magic;
		peOptionalHeader.baseAddress = ((_IMAGE_OPTIONAL_HEADER64*)PEoptionalHeaderBuffer)->ImageBase;
		peOptionalHeader.addressOfEntryPoint = ((_IMAGE_OPTIONAL_HEADER64*)PEoptionalHeaderBuffer)->AddressOfEntryPoint;
		peOptionalHeader.fileAlignment = ((_IMAGE_OPTIONAL_HEADER64*)PEoptionalHeaderBuffer)->FileAlignment;
		peOptionalHeader.memoryAlignment = ((_IMAGE_OPTIONAL_HEADER64*)PEoptionalHeaderBuffer)->SectionAlignment;
		peOptionalHeader.sizeOfImage = ((_IMAGE_OPTIONAL_HEADER64*)PEoptionalHeaderBuffer)->SizeOfImage;
		peOptionalHeader.sizeOfHeaders = ((_IMAGE_OPTIONAL_HEADER64*)PEoptionalHeaderBuffer)->SizeOfHeaders;
		peOptionalHeader.checkSum = ((_IMAGE_OPTIONAL_HEADER64*)PEoptionalHeaderBuffer)->CheckSum;
		peOptionalHeader.dllCharacteristic = ((_IMAGE_OPTIONAL_HEADER64*)PEoptionalHeaderBuffer)->DllCharacteristics;
	}

	cout << "Magic code: " << hex << peOptionalHeader.magic << endl;
	cout << "Base Address: " << hex << peOptionalHeader.baseAddress << endl;
	cout << "Entry Point: " << hex << peOptionalHeader.addressOfEntryPoint << endl;
	cout << "File Alignment: " << hex << peOptionalHeader.fileAlignment << endl;
	cout << "Memory Alignment: " << hex << peOptionalHeader.memoryAlignment << endl;
	cout << "Occupation Of Memory: " << hex << peOptionalHeader.sizeOfImage << endl;
	cout << "Size Of Headers using Disk Alignment: " << hex << peOptionalHeader.sizeOfHeaders << endl;
	cout << "Check Sum: " << hex << peOptionalHeader.checkSum << "  //System will check this when you modify the system file." << endl;
	cout << "dllCharacteristic: " << hex << peOptionalHeader.dllCharacteristic << endl;
	bitset<16> characteristicBitSet(peOptionalHeader.dllCharacteristic);
	cout << characteristicBitSet << endl;
	
	if (characteristicBitSet[6] == 1)
	{
		characteristicBitSet[6] = 0;
		cout << "This exe has dynamic base address\n";
	}
	if (characteristicBitSet[7] == 1)
	{
		cout << "System will check sum for this exe.\n";
	}

	return true;
}

bool PEWarrior::getSectionHeader()
{
	if (!MyFile->is_open())
	{
		return false;
	}

	sectionTables.setNumberOfSections(peFileHeader.numberOfSection);

	MyFile->seekg(dosPart.positionOfPESignature + 4 + sizeof(_IMAGE_FILE_HEADER) + peFileHeader.sizeOfOptionalHeader);
	
	_IMAGE_SECTION_HEADER* tablesAddress = new _IMAGE_SECTION_HEADER[peFileHeader.numberOfSection];
	MyFile->read((char*)tablesAddress, sizeof(_IMAGE_SECTION_HEADER) * peFileHeader.numberOfSection);

	sectionTables.setArrayStartAddress((_IMAGE_SECTION_HEADER*)tablesAddress);
	for (int i = 0; i < sectionTables.numberOfSections; i++)
	{
		cout << "------------------------------------------------------------" << endl;
		cout << "Section: " << sectionTables.tableArray[i].Name << endl;
		cout << "Entry in Memory: " << sectionTables.tableArray[i].VirtualAddress << endl;
		cout << "True Size in Memory: " << sectionTables.tableArray[i].Misc.VirtualSize << endl;
		cout << "Entry in File: " << sectionTables.tableArray[i].PointerToRawData << endl;
		cout << "Alignemnt Size in the file: " << sectionTables.tableArray[i].SizeOfRawData << endl;
		cout << "Characristic: " << hex << sectionTables.tableArray[i].Characteristics << endl;
		cout << "------------------------------------------------------------" << endl;
	}
	return false;
}

void PEWarrior::printTime(WORD timeStamp)
{
	time_t stamp = timeStamp;
	tm* structuredTime;
	structuredTime = gmtime(&stamp);

	char timeString[256];
	strftime(timeString, sizeof(timeString), "%Y-%m-%d %H:%M:%S", structuredTime);
}

void PEWarrior::reverseDllCharcateristic(int position)
{
	if (!MyFile->is_open())
	{
		return;
	}
	if ((position < 0) || (position > 15))
	{
		return;
	}

	void* optionalHeaderAddress = peOptionalHeader.getHeaeder();

	WORD dllChracteristic;
	if (peFileHeader.machine == 0x14c)
	{
		dllChracteristic = ((_IMAGE_OPTIONAL_HEADER*)optionalHeaderAddress)->DllCharacteristics;
	}
	else
	{
		dllChracteristic = ((_IMAGE_OPTIONAL_HEADER64*)optionalHeaderAddress)->DllCharacteristics;
	}

	bitset<16> characteristicBits(dllChracteristic);
	if (characteristicBits[position] == 0)
	{
		characteristicBits[position] = 1;
	}
	else {
		characteristicBits[position] = 0;
	}

	((_IMAGE_OPTIONAL_HEADER64*)optionalHeaderAddress)->DllCharacteristics = (WORD)characteristicBits.to_ulong();
	MyFile->seekp(dosPart.positionOfPESignature + 4 + sizeof(_IMAGE_FILE_HEADER));
	MyFile->write((char*)optionalHeaderAddress, peFileHeader.sizeOfOptionalHeader);
}


PEWarrior::SectionTables::~SectionTables()
{
	delete[] tableArray;
}

void PEWarrior::SectionTables::setArrayStartAddress(_IMAGE_SECTION_HEADER* tablesAddress)
{
	this->tableArray = tablesAddress;
}

void PEWarrior::SectionTables::setNumberOfSections(int num)
{
	this->numberOfSections = num;
}


void PEWarrior::PEOptionHeader::setHeader(void* headerAddress)
{
	this->peOptionalHeader = headerAddress;
}

void* PEWarrior::PEOptionHeader::getHeaeder()
{
	return this->peOptionalHeader;
}
