#pragma once
#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <fstream>
#include <math.h>
using namespace std;

class PEWarrior
{
public:
	PEWarrior(char* filePath);
	bool cheackPE();
	virtual ~PEWarrior();

private:
	fstream* MyFile = new fstream;
	int getHex(char* address, int size);
};