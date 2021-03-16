#include <Windows.h>
#include <fstream>
using namespace std;

typedef struct requiredFields
{
    WORD  typeCPU;        //04h  тип процессора
    WORD  flags;          //16h  указывает на предназначениеy
    WORD  subSystem;      //5Ch  операционная подсистема необходимая для запуска данного файла
    DWORD imageBase;      //34h  виртуальный начальный адрес загрузки программы (ее первого байта)
    DWORD imageSize;      //50h  виртуальный размер в байтах всего загружаемого образа 
    DWORD exportTableRVA; //78h  RVA адрес таблицы экспорта 
    DWORD importTableRVA; //80h  RVA адрес таблицы импорта
};

int main()
{
    LPCSTR fileName{ "D:/University/6 semester/Antivirus Methods and Tools/die_win64_portable/diec.exe" }; //exe file to parse
    HANDLE hFile;
    HANDLE hFileMapping;
    LPVOID lpFileBase;
    PIMAGE_DOS_HEADER dosHeader;
    PIMAGE_NT_HEADERS peHeader;

    PIMAGE_VXD_HEADER imageHeader;                    // for CPU Type and Flags
    PIMAGE_OPTIONAL_HEADER32 optionalHeader;          // for SubSystem, Image Base and Image Size
    PIMAGE_DELAYLOAD_DESCRIPTOR delayloaddescription; // for Import Table RVA

    requiredFields parsingData;


    // Создает или открывает каталог и возвращает дескриптор
    hFile = CreateFileA(fileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0); 
    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf("\n CreateFile failed in read mode \n");
        return 1;
    }


    // Создает или открывает объект отображенного в памяти (проецируемого) файла для заданного файла
    hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL); 
    if (hFileMapping == 0)
    {
        printf("\n CreateFileMapping failed \n");
        CloseHandle(hFile);
        return 1;
    }


    // Отображает представление проецируемого файла в адресное пространство вызывающего процесса
    lpFileBase = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0); 
    if (lpFileBase == 0)
    {
        printf("\n MapViewOfFile failed \n");
        CloseHandle(hFileMapping);
        CloseHandle(hFile);
        return 1;
    }




    // Указатель на заголовки dos
    dosHeader = (PIMAGE_DOS_HEADER)lpFileBase; 
    if (dosHeader->e_magic == IMAGE_DOS_SIGNATURE)
    {

        imageHeader = (PIMAGE_VXD_HEADER)((u_char*)dosHeader + dosHeader->e_lfanew);
        parsingData.typeCPU = imageHeader->e32_cpu;
        parsingData.flags = imageHeader->e32_mflags;
        printf("\t0x%x\t\tCPU Type\n", imageHeader->e32_cpu);
        printf("\t0x%x\t\tFlags\n", imageHeader->e32_mflags);

        optionalHeader = (PIMAGE_OPTIONAL_HEADER32)((u_char*)dosHeader + dosHeader->e_lfanew);
        parsingData.subSystem = optionalHeader->Subsystem;
        parsingData.imageBase = optionalHeader->ImageBase;
        parsingData.imageSize = optionalHeader->SizeOfImage;
        printf("\t0x%x\t\tSubSystem\n", optionalHeader->Subsystem);
        printf("\t0x%x\t\tImage Base\n", optionalHeader->ImageBase);
        printf("\t0x%x\t\tImage Size\n", optionalHeader->SizeOfImage);


        delayloaddescription = (PIMAGE_DELAYLOAD_DESCRIPTOR)((u_char*)dosHeader + dosHeader->e_lfanew);
        parsingData.importTableRVA = delayloaddescription->ImportNameTableRVA;
        printf("\t0x%x\t\tImport Table RVA\n", delayloaddescription->ImportNameTableRVA);
        

        // Отменяет отображение представления файла из адресного пространства вызывающего процесса
        UnmapViewOfFile(lpFileBase);
        CloseHandle(hFileMapping);
        CloseHandle(hFile);
        return 0;
    }
    else
    {
        printf("\n DOS Signature (MZ) Not Matched \n");
        UnmapViewOfFile(lpFileBase);
        CloseHandle(hFileMapping);
        CloseHandle(hFile);
        return 1;
    }
}