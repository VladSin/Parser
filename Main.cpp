#include <Windows.h>
#include <fstream>
#include <vector>
using namespace std;

typedef struct requiredFields {
    WORD  typeCPU;        //04h  тип процессора
    DWORD flags;          //16h  указывает на предназначениеy
    WORD  subSystem;      //5Ch  операционная подсистема необходимая для запуска данного файла
    DWORD imageBase;      //34h  виртуальный начальный адрес загрузки программы (ее первого байта)
    DWORD imageSize;      //50h  виртуальный размер в байтах всего загружаемого образа 
    DWORD exportTableRVA; //78h  RVA адрес таблицы экспорта 
    DWORD importTableRVA; //80h  RVA адрес таблицы импорта
};

typedef struct requiredImoprt {
    DWORD importName;
};

typedef struct requiredSection {
    DWORD sectionName;
};

PIMAGE_SECTION_HEADER GetEnclosingSectionHeader(DWORD rva, PIMAGE_NT_HEADERS pNTHeader){
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(pNTHeader);
    for (unsigned i = 0; i < pNTHeader->FileHeader.NumberOfSections; i++, section++){
        if ((rva >= section->VirtualAddress) && (rva < (section->VirtualAddress + section->Misc.VirtualSize)))
            return section;
    }
    return 0;
}

void fileRecording(requiredFields parsingData, string fileData) {
    printf("\n INFO \t\t Saving Data \n");

    ofstream recordData;       
    recordData.open(fileData);

    if (recordData.is_open()) {
        recordData << " CPU Type: "         << parsingData.typeCPU         << endl;
        recordData << " Flags: "            << parsingData.flags           << endl;
        recordData << " SubSystem: "        << parsingData.subSystem       << endl;
        recordData << " Image Base: "       << parsingData.imageBase       << endl;
        recordData << " Image Size: "       << parsingData.imageSize       << endl;
        recordData << " Export Table RVA: " << parsingData.exportTableRVA  << endl;
        recordData << " Import Table RVA: " << parsingData.importTableRVA  << endl;
    }
    else {
        printf(" INFO \t\t Saving Data Error\n");
    }
    printf(" INFO \t\t Save Data Successfully \n\n");
}

void jsonRecording(requiredFields parsingData, string fileData) {
    printf("\n INFO \t\t Saving Data \n");
    ofstream recordData;
    recordData.open(fileData);

    recordData << "{\n";
   
    if (recordData.is_open()) {
        recordData << "\t\"" << "cputype"   << "\" : \"" << parsingData.typeCPU        << "\",\n";
        recordData << "\t\"" << "flags"     << "\" : \"" << parsingData.flags          << "\",\n";
        recordData << "\t\"" << "imgbase"   << "\" : \"" << parsingData.imageBase      << "\",\n";
        recordData << "\t\"" << "imagesize" << "\" : \"" << parsingData.imageSize      << "\",\n";
        recordData << "\t\"" << "subsystem" << "\" : \"" << parsingData.subSystem      << "\",\n";
        recordData << "\t\"" << "exprva"    << "\" : \"" << parsingData.exportTableRVA << "\",\n";
        recordData << "\t\"" << "imprva"    << "\" : \"" << parsingData.importTableRVA << "\" \n";
    }
    else {
        printf(" INFO \t\t Saving Data Error\n");
    }

    recordData << "}";

    printf(" INFO \t\t Save Data Successfully \n\n");
    recordData.close();
}

void jsonRecordingWithImports(requiredFields parsingData, vector<requiredSection> sectionData, vector<requiredImoprt> importData,  string fileData) {
    printf("\n INFO \t\t Saving Data \n");
    ofstream recordData;
    recordData.open(fileData);

    recordData << "{\n";

    if (recordData.is_open()) {
        recordData << "\t\"" << "cputype"   << "\" : \"" << "0x" << hex << parsingData.typeCPU        << "\",\n";
        recordData << "\t\"" << "flags"     << "\" : \"" << "0x" << hex << parsingData.flags          << "\",\n";
        recordData << "\t\"" << "imgbase"   << "\" : \"" << "0x" << hex << parsingData.imageBase      << "\",\n";
        recordData << "\t\"" << "imagesize" << "\" : \"" << "0x" << hex << parsingData.imageSize      << "\",\n";
        recordData << "\t\"" << "subsystem" << "\" : \"" << "0x" << hex << parsingData.subSystem      << "\",\n";
        recordData << "\t\"" << "exprva"    << "\" : \"" << "0x" << hex << parsingData.exportTableRVA << "\",\n";
        recordData << "\t\"" << "imprva"    << "\" : \"" << "0x" << hex << parsingData.importTableRVA << "\",\n";
        
        recordData << "\t\"" << "sections" << "\" : \n";
        recordData << "\t" << "[\n";
        for (size_t i = 0; i < sectionData.size() - 1; i++) {
            recordData << "\t\t\"" << "0x" << hex << sectionData.at(i).sectionName << "\",\n";
        }
        recordData << "\t\t\"" << "0x" << hex << sectionData.at(sectionData.size() - 1).sectionName << "\"\n";
        recordData << "\t" << "],\n";

        recordData << "\t\"" << "imports"  << "\" : \n";
        recordData << "\t" << "[\n";
        for (size_t i = 0; i < importData.size() - 1; i++) {
            recordData << "\t\t\"" << "0x" << hex << importData.at(i).importName << "\",\n";
        }
        recordData << "\t\t\"" << "0x" << hex << importData.at(importData.size()-1).importName << "\"\n";
        recordData << "\t" << "]\n";
    }
    else {
        printf(" INFO \t\t Saving Data Error\n");
    }

    recordData << "}";

    printf(" INFO \t\t Save Data Successfully \n\n");
    recordData.close();
}

int checkArgumets(int argc, char* argv[], char*& in, char*& out)
{
    if (argc < 3) {
        printf(" ERROR \t\t Not enough arguments!\n");
        return 1;
    }

    if (!strcmp(argv[1], "-al")) {
        in = argv[2];
        out = argv[3];
    }
    else {
        in = argv[1];
        out = argv[2];
    }
    return 0;
}

int main(int argc, char* argv[]) {
    LPCSTR fileName = "D:/University/6 semester/Antivirus Methods and Tools/Parser/Debug/die.exe" ;     //exe file to parse
    string fileData = "D:/University/6 semester/Antivirus Methods and Tools/Parser/Debug/jsonData.txt"; //jspn file to write

    /*char* inputPath = argv[1];
    char* outputPath = argv[2];
    int exception = checkArgumets(argc, argv, inputPath, outputPath);
    if (exception != 0) {
        return -1;
    }

    LPCSTR fileName = inputPath;          //exe file to parse
    string fileData = outputPath;         //json file to write*/

    HANDLE hFile;
    HANDLE hFileMapping;
    LPVOID lpFileBase;

    PIMAGE_DOS_HEADER           dosHeader;
    PIMAGE_NT_HEADERS           peHeader;

    PIMAGE_THUNK_DATA           thunk;
    PIMAGE_IMPORT_BY_NAME       pOrdinalName;
    PIMAGE_IMPORT_DESCRIPTOR    importDesc;
    PIMAGE_SECTION_HEADER       pSection;
    PIMAGE_SECTION_HEADER       sectionHeader;


    PIMAGE_VXD_HEADER           imageHeader;          // for CPU Type and Flags                  
    PIMAGE_OPTIONAL_HEADER32    optionalHeader;       // for SubSystem, Image Base and Image Size                     
    PIMAGE_EXPORT_DIRECTORY     exportDirection;      // for Export Table RVA

    requiredFields parsingData;
    vector<requiredImoprt> vectorImportData;
    vector<requiredSection> vectorSectionData;


    // Создает или открывает каталог и возвращает дескриптор
    hFile = CreateFileA(fileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0); 
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("\n CreateFile failed in read mode \n");
        return 1;
    }

    // Создает или открывает объект отображенного в памяти (проецируемого) файла для заданного файла
    hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL); 
    if (hFileMapping == 0) {
        printf("\n CreateFileMapping failed \n");
        CloseHandle(hFile);
        return 1;
    }

    // Отображает представление проецируемого файла в адресное пространство вызывающего процесса
    lpFileBase = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0); 
    if (lpFileBase == 0) {
        printf("\n MapViewOfFile failed \n");
        CloseHandle(hFileMapping);
        CloseHandle(hFile);
        return 1;
    }

    // Указатель на заголовки DOS
    dosHeader = (PIMAGE_DOS_HEADER)lpFileBase; 
    if (dosHeader->e_magic == IMAGE_DOS_SIGNATURE) {
        printf("\n DOS Signature (MZ) Matched");

        peHeader = (PIMAGE_NT_HEADERS)((u_char*)dosHeader + dosHeader->e_lfanew);
        if (peHeader->Signature == IMAGE_NT_SIGNATURE) {
            printf("\n PE  Signature (PE) Matched \n\n");

            printf("\n Selected Fields Data:  \n");
            imageHeader = (PIMAGE_VXD_HEADER)((u_char*)dosHeader + dosHeader->e_lfanew);
            parsingData.typeCPU = imageHeader->e32_cpu;
            parsingData.flags = imageHeader->e32_mflags;
            printf("CPU Type\t\t0x%x\n", imageHeader->e32_cpu);
            printf("Flags\t\t\t0x%x\n", imageHeader->e32_mflags);

            optionalHeader = (PIMAGE_OPTIONAL_HEADER32)((u_char*)dosHeader + dosHeader->e_lfanew);
            parsingData.subSystem = optionalHeader->Subsystem;
            parsingData.imageBase = optionalHeader->ImageBase;
            parsingData.imageSize = optionalHeader->SizeOfImage;
            printf("SubSystem\t\t0x%x\n", optionalHeader->Subsystem);
            printf("Image Base\t\t0x%x\n", optionalHeader->ImageBase);
            printf("Image Size\t\t0x%x\n", optionalHeader->SizeOfImage);

            DWORD importsStartRVA = peHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
            parsingData.importTableRVA = importsStartRVA;
            printf("Import Table RVA\t0x%x\n", importsStartRVA);


            exportDirection = (PIMAGE_EXPORT_DIRECTORY)((u_char*)dosHeader + dosHeader->e_lfanew);
            parsingData.exportTableRVA= exportDirection->AddressOfNames;
            printf("Export Table RVA\t0x%x\n", exportDirection->AddressOfNames);
            
            //jsonRecording(parsingData, fileData);
        }   


        peHeader = (PIMAGE_NT_HEADERS)((u_char*)dosHeader + dosHeader->e_lfanew);
        if (peHeader->Signature == IMAGE_NT_SIGNATURE) {
            
            // RVA-адрес таблицы импорта
            DWORD importsStartRVA = peHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
            if (!importsStartRVA) {
                printf("\n RVA-address of import table not found");
                UnmapViewOfFile(lpFileBase);
                CloseHandle(hFileMapping);
                CloseHandle(hFile);
                return 0;
            }
            
            // Определение адреса секции
            pSection = GetEnclosingSectionHeader(importsStartRVA, peHeader);
            if (!pSection) {
                printf("\n Sections address not found");
                UnmapViewOfFile(lpFileBase);
                CloseHandle(hFileMapping);
                CloseHandle(hFile);
                return 0;
            }


            printf("\n Selected Sections Data:  \n");
            requiredSection sectionDate;
            sectionHeader = IMAGE_FIRST_SECTION(peHeader); // Первый адрес секции 
            UINT nSectionCount = peHeader->FileHeader.NumberOfSections;
            
            // Производим перебор списка 
            int checkFlag = 0;
            for (UINT i = 0; i <= nSectionCount; i++, sectionHeader++){
                if ((sectionHeader->VirtualAddress) > peHeader->OptionalHeader.AddressOfEntryPoint){
                    if (checkFlag == 0) {
                        sectionHeader--;
                        printf("%s\n", (PBYTE)(sectionHeader->Name));
                        sectionDate.sectionName = (DWORD)sectionHeader->Name;
                        vectorSectionData.push_back(sectionDate);
                        checkFlag += 1;
                    }
                    printf("%s\n", (PBYTE)(sectionHeader->Name));
                    sectionDate.sectionName = (DWORD)sectionHeader->Name;
                    vectorSectionData.push_back(sectionDate);
                }
            }


            printf("\n Selected Imports Data:  \n");
            DWORD delta = pSection->VirtualAddress - pSection->PointerToRawData;
            importDesc = (PIMAGE_IMPORT_DESCRIPTOR)(importsStartRVA - delta + (u_char*)lpFileBase);

            // Производим перебор списка 
            while (importDesc->TimeDateStamp || importDesc->Name){
                requiredImoprt importData; 
                printf("%s\n", (PBYTE)(importDesc->Name) - (PBYTE)delta + (PBYTE)lpFileBase);
                importData.importName = importDesc->Name;
                importDesc++;
                vectorImportData.push_back(importData);
            }
            jsonRecordingWithImports(parsingData, vectorSectionData, vectorImportData, fileData);
        } 
        

        // Отменяет отображение представления файла из адресного пространства вызывающего процесса
        UnmapViewOfFile(lpFileBase);
        CloseHandle(hFileMapping);
        CloseHandle(hFile);
        return 0;
    }
    else {
        printf("\n DOS Signature (MZ) Not Matched \n");
        UnmapViewOfFile(lpFileBase);
        CloseHandle(hFileMapping);
        CloseHandle(hFile);
        return 1;
    }
}