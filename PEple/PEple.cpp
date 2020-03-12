// Author: Absolutelycold
// https://github.com/absolutelycold
// Date: 03/08/2020

#include <iostream>
#include "PEWarrior.h"

int main()
{
    char* filePath = new char[1024];
    cout << "Path:";
    cin >> filePath;
    //cout << "Your input path: " << filePath << endl;
    PEWarrior peWarrior(filePath);
    //peWarrior.setDllCharcateristic(6, 0);
    //peWarrior.modifyEntryPoint(0x1180);
    //peWarrior.checkPE();
    //peWarrior.extendLastSection(0x50);
    //peWarrior.injectMessageBoxA32AtEnd(0x76cc0c30);
    //peWarrior.addASection(0x600);
    //peWarrior.combineSectonToOne();
    //BYTE shellCode[] = { 0x6a, 0x00, 0x6a, 0x00,  0x6a, 0x00,  0x6a, 0x00, 0xe8, 0x23, 0xfc, 0x7a, 0x76 };
    //peWarrior.inject32(0x107c00, shellCode, sizeof(shellCode));
    //delete[] filePath;
    /*peWarrior.setSectionCharacteristic(0, 6, 1);
    peWarrior.setSectionCharacteristic(0, 7, 1);
    peWarrior.setSectionCharacteristic(0, 6, 1);
    peWarrior.setSectionCharacteristic(0, 29, 1);
    peWarrior.setSectionCharacteristic(0, 30, 1);
    peWarrior.setSectionCharacteristic(0, 31, 1);*/
    //cout << "Plus address:" << peWarrior.getExportFunctionAddressByName((char*)"_Divide@8") << endl;
    //cout << peWarrior.getExportFunctionAddressByOrdinal(13) << endl;
    return EXIT_SUCCESS;
}
