#include "PEWarrior.h"

PEWarrior::PEWarrior(char* filePath)
{
	this->MyFile->open(filePath, ios::binary | ios::in);
	if (!this->MyFile->is_open())
	{
		cout << "Cannot open the file.\n";
	}
}

bool PEWarrior::cheackPE()
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
		cout << "this is mz file\n";
	}

	// The Position of PE Symbol is in the 60 bytes of the file
	char PESybolPosition[1];
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
