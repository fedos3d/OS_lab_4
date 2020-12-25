using System;
using System.Collections;
using System.Collections.Generic;
using System.Data.Common;
using System.IO;
using System.Linq;
using System.Reflection.PortableExecutable;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices.ComTypes;
using System.Security.Authentication.ExtendedProtection;
using System.Text;
using System.Threading;
using System.Transactions;
using Microsoft.VisualBasic.CompilerServices;

namespace OS_lab4
{
    class Program
    {
        //constants for dirs
        public const int IMAGE_DIRECTORY_ENTRY_EXPORT = 0;
        public const int IMAGE_DIRECTORY_ENTRY_IMPORT = 1;    
        public const int IMAGE_DIRECTORY_ENTRY_RESOURCE = 2;
        public const int IMAGE_DIRECTORY_ENTRY_EXCEPTION = 3;
        public const int IMAGE_DIRECTORY_ENTRY_SECURITY = 4; 
        public const int IMAGE_DIRECTORY_ENTRY_BASERELOC = 5;
        public const int IMAGE_DIRECTORY_ENTRY_DEBUG = 6;   
        //      IMAGE_DIRECTORY_ENTRY_COPYRIGHT               7
        public const int IMAGE_DIRECTORY_ENTRY_ARCHITECTURE = 7;
        public const int IMAGE_DIRECTORY_ENTRY_GLOBALPTR = 8;    
        public const int IMAGE_DIRECTORY_ENTRY_TLS = 9;          
        public const int IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG = 10; 
        public const int IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT = 11;
        public const int IMAGE_DIRECTORY_ENTRY_IAT = 12;
        public const int IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT = 13; 
        public const int IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14;
        
        //flags
        public static bool showReloc = false;
        public static bool showSections = false;
        public static bool showHeaderInfo = false;
        public static bool showSymbolsInfo = false;
        public static bool showImportExportInfo = false;

        
        public static bool hassymbols = false;
        public static bool if32 = false;
        public static String fileName = "";
        public static String Arch = "architecture: ";
        public static String Bitnost = "file type: ";
        public static SectionHeader[] sectionHeaders;
        public static uint alingment = 0;
        public static FileHeader fileheader;
        public static OptionalHeader64 optionalHeader64 = new OptionalHeader64();
        public static OptionalHeader32 optionalHeader32 = new OptionalHeader32();
        
        public static SymbolTable[] SymbolTables;
        public static List<BaseRelocationBlock> baseRelocationBlocks = new List<BaseRelocationBlock>();
        
        static void Main(string[] args)
        {
            //Console.WriteLine("Enter name of your file: ");
            string kek;
            //Console.ReadLine();
            kek = "64.exe";
            //Console.WriteLine(kek);
            fileName = kek;
            Console.WriteLine("Set params: (r - show relocation, s - show sections info, f - show header info, t - show symbols info, p - show import and export info) Example: rsftp - will show everything (!Leave empty for basic info)");
            String paramss = Console.ReadLine();
            if (paramss.Contains('r'))
            {
                showReloc = true;
            }

            if (paramss.Contains('s'))
            {
                showSections = true;
            }

            if (paramss.Contains('f'))
            {
                showHeaderInfo = true;
            }

            if (paramss.Contains('t'))
            {
                showSymbolsInfo = true;
            }

            if (paramss.Contains('p'))
            {
                showImportExportInfo = true;
            }
            if (File.Exists(fileName))
            {
                if (File.ReadAllBytes(fileName).Length != 0)
                {
                    using (BinaryReader reader = new BinaryReader(File.Open(fileName, FileMode.Open)))
                    {
                        var e_magic = new byte[2]; //magic to see if it's really a PE file
                        for (int i = 0; i < 2; i++)
                        {
                            e_magic[i] = reader.ReadByte();
                        }
                        if (checkExecutable(e_magic))
                        {
                            var e_lfanew = new byte[4]; //here we read our pe offest it's a PE offset
                            
                            reader.BaseStream.Seek(60, SeekOrigin.Begin);
                            reader.Read(e_lfanew, 0, 4);
                            Array.Reverse(e_lfanew);
                            long offset = Int32.Parse(Convert.ToHexString(e_lfanew),
                                System.Globalization.NumberStyles.HexNumber);

                            //now let's double check that it's a PE file by checking signature
                            var signature = new byte[4];
                            reader.BaseStream.Seek(offset, SeekOrigin.Begin);
                            reader.Read(signature, 0, 4);
                            if (checkSignature(signature))
                            {
                                //here we fill our header file
                                fileheader = new FileHeader(); //let's create file header
                                //machine type:
                                var machine = new byte[2];
                                reader.Read(machine, 0, 2);
                                Array.Reverse(machine);
                                setArchType(machine);
                                fileheader.Machine = UInt16.Parse(Convert.ToHexString(machine),
                                System.Globalization.NumberStyles.HexNumber);
                                //num of sec
                                var numofsec = new byte[2];
                                reader.Read(numofsec, 0, 2);
                                Array.Reverse(numofsec);
                                fileheader.NumberOfSections = UInt16.Parse(Convert.ToHexString(numofsec),
                                    System.Globalization.NumberStyles.HexNumber);
                                //size of optional header
                                fileheader.TimeDateStamp = UInt32.Parse(Convert.ToHexString(reverser(reader.ReadBytes(4))), System.Globalization.NumberStyles.HexNumber);
                                fileheader.PointerToSymbolTable = UInt32.Parse(Convert.ToHexString(reverser(reader.ReadBytes(4))), System.Globalization.NumberStyles.HexNumber);
                                fileheader.NumberOfSymbols = UInt32.Parse(Convert.ToHexString(reverser(reader.ReadBytes(4))), System.Globalization.NumberStyles.HexNumber);
                                if (fileheader.PointerToSymbolTable != 0)
                                {
                                    hassymbols = true;
                                }
                                    var sizeofoptheader = new byte[2];
                                    reader.Read(sizeofoptheader, 0, 2);
                                    Array.Reverse(sizeofoptheader);
                                    fileheader.SizeOfOptionalHeader = UInt16.Parse(Convert.ToHexString(sizeofoptheader),
                                    System.Globalization.NumberStyles.HexNumber);
                                    //characteristics
                                    var chara = new byte[2];
                                    reader.Read(chara, 0, 2);
                                    Array.Reverse(chara);
                                    fileheader.Characteristics = UInt16.Parse(Convert.ToHexString(sizeofoptheader),
                                    System.Globalization.NumberStyles.HexNumber);
                                
                                    //now well be filling out OPTIONAL HEADER
                                
                                    var magic = reader.ReadBytes(2);
                                    Array.Reverse(magic);
                                    setMagic(magic);
                                    if (Convert.ToHexString(magic) == "010B" || Convert.ToHexString(magic) == "0107")
                                    {
                                    if32 = true;
                                    optionalHeader32.Magic = UInt16.Parse(Convert.ToHexString(reverser(magic)),
                                    System.Globalization.NumberStyles.HexNumber);
                                    optionalHeader32.MajorLinkerVersion = reader.ReadByte(); //major linker version
                                    optionalHeader32.MinorLinkerVersion = reader.ReadByte(); //minor linker version
                                    optionalHeader32.SizeOfCode = UInt32.Parse(Convert.ToHexString(reverser(reader.ReadBytes(4))), System.Globalization.NumberStyles.HexNumber);
                                    optionalHeader32.SizeOfInitializedData = UInt32.Parse(Convert.ToHexString(reverser(reader.ReadBytes(4))), System.Globalization.NumberStyles.HexNumber);
                                    optionalHeader32.SizeOfUninitializedData = UInt32.Parse(Convert.ToHexString(reverser(reader.ReadBytes(4))), System.Globalization.NumberStyles.HexNumber);
                                    optionalHeader32.AddressOfEntryPoint = UInt32.Parse(Convert.ToHexString(reverser(reader.ReadBytes(4))), System.Globalization.NumberStyles.HexNumber);
                                    optionalHeader32.BaseOfCode = UInt32.Parse(Convert.ToHexString(reverser(reader.ReadBytes(4))), System.Globalization.NumberStyles.HexNumber);
                                    optionalHeader32.BaseOfData = UInt32.Parse(Convert.ToHexString(reverser(reader.ReadBytes(4))), System.Globalization.NumberStyles.HexNumber);
                                    optionalHeader32.ImageBase = UInt32.Parse(Convert.ToHexString(reverser(reader.ReadBytes(4))), System.Globalization.NumberStyles.HexNumber);
                                    optionalHeader32.SectionAlignment = UInt32.Parse(Convert.ToHexString(reverser(reader.ReadBytes(4))), System.Globalization.NumberStyles.HexNumber);
                                    optionalHeader32.FileAlignment = UInt32.Parse(Convert.ToHexString(reverser(reader.ReadBytes(4))), System.Globalization.NumberStyles.HexNumber);
                                    optionalHeader32.MajorOperatingSystemVersion = UInt16.Parse(Convert.ToHexString(reverser(reader.ReadBytes(2))), System.Globalization.NumberStyles.HexNumber);
                                    optionalHeader32.MinorOperatingSystemVersion = UInt16.Parse(Convert.ToHexString(reverser(reader.ReadBytes(2))), System.Globalization.NumberStyles.HexNumber);
                                    optionalHeader32.MajorImageVersion = UInt16.Parse(Convert.ToHexString(reverser(reader.ReadBytes(2))), System.Globalization.NumberStyles.HexNumber);
                                    optionalHeader32.MinorImageVersion = UInt16.Parse(Convert.ToHexString(reverser(reader.ReadBytes(2))), System.Globalization.NumberStyles.HexNumber);
                                    optionalHeader32.MajorSubsystemVersion = UInt16.Parse(Convert.ToHexString(reverser(reader.ReadBytes(2))), System.Globalization.NumberStyles.HexNumber);
                                    optionalHeader32.MinorSubsystemVersion = UInt16.Parse(Convert.ToHexString(reverser(reader.ReadBytes(2))), System.Globalization.NumberStyles.HexNumber);
                                    optionalHeader32.Win32VersionValue = UInt32.Parse(Convert.ToHexString(reverser(reader.ReadBytes(4))), System.Globalization.NumberStyles.HexNumber);
                                    optionalHeader32.SizeOfImage = UInt32.Parse(Convert.ToHexString(reverser(reader.ReadBytes(4))), System.Globalization.NumberStyles.HexNumber);
                                    optionalHeader32.SizeOfHeaders = UInt32.Parse(Convert.ToHexString(reverser(reader.ReadBytes(4))), System.Globalization.NumberStyles.HexNumber);
                                    optionalHeader32.CheckSum = UInt32.Parse(Convert.ToHexString(reverser(reader.ReadBytes(4))),System.Globalization.NumberStyles.HexNumber);
                                    optionalHeader32.Subsystem = UInt16.Parse(Convert.ToHexString(reverser(reader.ReadBytes(2))), System.Globalization.NumberStyles.HexNumber);
                                    optionalHeader32.DllCharacteristics = UInt16.Parse(Convert.ToHexString(reverser(reader.ReadBytes(2))), System.Globalization.NumberStyles.HexNumber);
                                    optionalHeader32.SizeOfStackReserve = UInt32.Parse(Convert.ToHexString(reverser(reader.ReadBytes(4))), System.Globalization.NumberStyles.HexNumber);
                                    optionalHeader32.SizeOfStackCommit = UInt32.Parse(Convert.ToHexString(reverser(reader.ReadBytes(4))), System.Globalization.NumberStyles.HexNumber);
                                    optionalHeader32.SizeOfHeapReserve = UInt32.Parse(
                                        Convert.ToHexString(reverser(reader.ReadBytes(4))),
                                        System.Globalization.NumberStyles.HexNumber);
                                    optionalHeader32.SizeOfHeapCommit = UInt32.Parse(Convert.ToHexString(reverser(reader.ReadBytes(4))), System.Globalization.NumberStyles.HexNumber);
                                    optionalHeader32.LoaderFlags = UInt32.Parse(Convert.ToHexString(reverser(reader.ReadBytes(4))), System.Globalization.NumberStyles.HexNumber);
                                    optionalHeader32.NumberOfRvaAndSizes = UInt32.Parse(Convert.ToHexString(reverser(reader.ReadBytes(4))), System.Globalization.NumberStyles.HexNumber);
                                
                                } else if (Convert.ToHexString(magic) == "020B")
                                {
                                    if32 = false;
                                    optionalHeader64.Magic = UInt16.Parse(Convert.ToHexString(reverser(magic)),
                                    System.Globalization.NumberStyles.HexNumber);
                                    optionalHeader64.MajorLinkerVersion = reader.ReadByte(); //major linker version
                                    optionalHeader64.MinorLinkerVersion = reader.ReadByte(); //minor linker version
                                    optionalHeader64.SizeOfCode = UInt32.Parse(Convert.ToHexString(reverser(reader.ReadBytes(4))), System.Globalization.NumberStyles.HexNumber);
                                    optionalHeader64.SizeOfInitializedData = UInt32.Parse(Convert.ToHexString(reverser(reader.ReadBytes(4))), System.Globalization.NumberStyles.HexNumber);
                                    optionalHeader64.SizeOfUninitializedData = UInt32.Parse(Convert.ToHexString(reverser(reader.ReadBytes(4))), System.Globalization.NumberStyles.HexNumber);
                                    optionalHeader64.AddressOfEntryPoint = UInt32.Parse(Convert.ToHexString(reverser(reader.ReadBytes(4))), System.Globalization.NumberStyles.HexNumber);
                                    optionalHeader64.BaseOfCode = UInt32.Parse(Convert.ToHexString(reverser(reader.ReadBytes(4))), System.Globalization.NumberStyles.HexNumber);
                                    optionalHeader64.ImageBase = UInt64.Parse(Convert.ToHexString(reverser(reader.ReadBytes(8))), System.Globalization.NumberStyles.HexNumber);
                                    optionalHeader64.SectionAlignment = UInt32.Parse(Convert.ToHexString(reverser(reader.ReadBytes(4))), System.Globalization.NumberStyles.HexNumber);
                                    optionalHeader64.FileAlignment = UInt32.Parse(Convert.ToHexString(reverser(reader.ReadBytes(4))), System.Globalization.NumberStyles.HexNumber);
                                    optionalHeader64.MajorOperatingSystemVersion = UInt16.Parse(Convert.ToHexString(reverser(reader.ReadBytes(2))), System.Globalization.NumberStyles.HexNumber);
                                    optionalHeader64.MinorOperatingSystemVersion = UInt16.Parse(Convert.ToHexString(reverser(reader.ReadBytes(2))), System.Globalization.NumberStyles.HexNumber);
                                    optionalHeader64.MajorImageVersion = UInt16.Parse(Convert.ToHexString(reverser(reader.ReadBytes(2))), System.Globalization.NumberStyles.HexNumber);
                                    optionalHeader64.MinorImageVersion = UInt16.Parse(Convert.ToHexString(reverser(reader.ReadBytes(2))), System.Globalization.NumberStyles.HexNumber);
                                    optionalHeader64.MajorSubsystemVersion = UInt16.Parse(Convert.ToHexString(reverser(reader.ReadBytes(2))), System.Globalization.NumberStyles.HexNumber);
                                    optionalHeader64.MinorSubsystemVersion = UInt16.Parse(Convert.ToHexString(reverser(reader.ReadBytes(2))), System.Globalization.NumberStyles.HexNumber);
                                    optionalHeader64.Win32VersionValue = UInt32.Parse(Convert.ToHexString(reverser(reader.ReadBytes(4))), System.Globalization.NumberStyles.HexNumber);
                                    optionalHeader64.SizeOfImage = UInt32.Parse(Convert.ToHexString(reverser(reader.ReadBytes(4))), System.Globalization.NumberStyles.HexNumber);
                                    optionalHeader64.SizeOfHeaders = UInt32.Parse(Convert.ToHexString(reverser(reader.ReadBytes(4))), System.Globalization.NumberStyles.HexNumber);
                                    optionalHeader64.CheckSum = UInt32.Parse(Convert.ToHexString(reverser(reader.ReadBytes(4))),System.Globalization.NumberStyles.HexNumber);
                                    optionalHeader64.Subsystem = UInt16.Parse(Convert.ToHexString(reverser(reader.ReadBytes(2))), System.Globalization.NumberStyles.HexNumber);
                                    optionalHeader64.DllCharacteristics = UInt16.Parse(Convert.ToHexString(reverser(reader.ReadBytes(2))), System.Globalization.NumberStyles.HexNumber);
                                    optionalHeader64.SizeOfStackReserve = UInt64.Parse(Convert.ToHexString(reverser(reader.ReadBytes(8))), System.Globalization.NumberStyles.HexNumber);
                                    optionalHeader64.SizeOfStackCommit = UInt64.Parse(Convert.ToHexString(reverser(reader.ReadBytes(8))), System.Globalization.NumberStyles.HexNumber);
                                    optionalHeader64.SizeOfHeapReserve = UInt64.Parse(
                                        Convert.ToHexString(reverser(reader.ReadBytes(8))),
                                        System.Globalization.NumberStyles.HexNumber);
                                    optionalHeader64.SizeOfHeapCommit = UInt64.Parse(Convert.ToHexString(reverser(reader.ReadBytes(8))), System.Globalization.NumberStyles.HexNumber);
                                    optionalHeader64.LoaderFlags = UInt32.Parse(Convert.ToHexString(reverser(reader.ReadBytes(4))), System.Globalization.NumberStyles.HexNumber);
                                    optionalHeader64.NumberOfRvaAndSizes = UInt32.Parse(Convert.ToHexString(reverser(reader.ReadBytes(4))), System.Globalization.NumberStyles.HexNumber);
                                }
                                else
                                {
                                    throw new SomethingWentWrongException();
                                }
                                //lets fill out DIR
                                uint n = 0;
                                if (if32)
                                {
                                    n = optionalHeader32.NumberOfRvaAndSizes;
                                }
                                else
                                {
                                    n = optionalHeader64.NumberOfRvaAndSizes;
                                }
                                DataDericotry[] dat = new DataDericotry[n];
                                for (int i = 0; i < n; i++)
                                {
                                    uint va = UInt32.Parse(Convert.ToHexString(reverser(reader.ReadBytes(4))),
                                        System.Globalization.NumberStyles.HexNumber);
                                    uint sz = UInt32.Parse(Convert.ToHexString(reverser(reader.ReadBytes(4))),
                                        System.Globalization.NumberStyles.HexNumber);
                                    var lol = new DataDericotry();
                                    lol.Size = sz;
                                    lol.VirtualAddress = va;
                                    dat[i] = lol;
                                }

                                if (if32)
                                {
                                    optionalHeader32._dataDericotry = dat;
                                }
                                else
                                {
                                    optionalHeader64._dataDericotry = dat;
                                }
                                //now lets fill out section headers
                                sectionHeaders = new SectionHeader[fileheader.NumberOfSections];
                                for (int i = 0; i < fileheader.NumberOfSections; i++)
                                {
                                    var newSectionHeader = new SectionHeader();
                                    newSectionHeader.Name = reader.ReadBytes(8);
                                    newSectionHeader.PhysicalAddress = newSectionHeader.VirtualSize =
                                        UInt32.Parse(Convert.ToHexString(reverser(reader.ReadBytes(4))),
                                            System.Globalization.NumberStyles.HexNumber);
                                    newSectionHeader.VirtualAddress = UInt32.Parse(Convert.ToHexString(reverser(reader.ReadBytes(4))), 
                                        System.Globalization.NumberStyles.HexNumber);
                                    newSectionHeader.SizeOfRawData = UInt32.Parse(Convert.ToHexString(reverser(reader.ReadBytes(4))), System.Globalization.NumberStyles.HexNumber);
                                    newSectionHeader.PointerToRawData = UInt32.Parse(Convert.ToHexString(reverser(reader.ReadBytes(4))), System.Globalization.NumberStyles.HexNumber);
                                    newSectionHeader.PointerToRelocations = UInt32.Parse(Convert.ToHexString(reverser(reader.ReadBytes(4))), System.Globalization.NumberStyles.HexNumber);
                                    newSectionHeader.PointerToLinenumbers = UInt32.Parse(Convert.ToHexString(reverser(reader.ReadBytes(4))), System.Globalization.NumberStyles.HexNumber);
                                    newSectionHeader.NumberOfRelocations = UInt16.Parse(Convert.ToHexString(reverser(reader.ReadBytes(2))), System.Globalization.NumberStyles.HexNumber);
                                    newSectionHeader.NumberOfLinenumbers = UInt16.Parse(Convert.ToHexString(reverser(reader.ReadBytes(2))), System.Globalization.NumberStyles.HexNumber);
                                    newSectionHeader.Characteristics = UInt32.Parse(Convert.ToHexString(reverser(reader.ReadBytes(4))), System.Globalization.NumberStyles.HexNumber);
                                    sectionHeaders[i] = newSectionHeader;
                                }
                                if (if32)
                                {
                                    alingment = optionalHeader32.SectionAlignment;
                                }
                                else
                                {
                                    alingment = optionalHeader64.SectionAlignment;
                                }
                                //somewhre here i should read symbol table //TODO:reading symbol table
                                if (fileheader.PointerToSymbolTable != 0)
                                {
                                    SymbolTables = new SymbolTable[fileheader.NumberOfSymbols];
                                    var curpos = reader.BaseStream.Position;
                                    reader.BaseStream.Seek(fileheader.PointerToSymbolTable, SeekOrigin.Begin);
                                    for (int i = 0; i < fileheader.NumberOfSymbols; i++)
                                    {
                                        var cur = new SymbolTable();
                                        cur.Name = reader.ReadBytes(8);
                                        cur.Value = UInt32.Parse(Convert.ToHexString(reverser(reader.ReadBytes(4))), System.Globalization.NumberStyles.HexNumber);
                                        cur.SectionNumber = Int16.Parse(Convert.ToHexString(reverser(reader.ReadBytes(2))), System.Globalization.NumberStyles.HexNumber);
                                        cur.Type = UInt16.Parse(Convert.ToHexString(reverser(reader.ReadBytes(2))), System.Globalization.NumberStyles.HexNumber);
                                        cur.StorageClass = Byte.Parse(Convert.ToHexString(reverser(reader.ReadBytes(1))), System.Globalization.NumberStyles.HexNumber);
                                        cur.NumberOfAuxSymbols = Byte.Parse(Convert.ToHexString(reverser(reader.ReadBytes(1))), System.Globalization.NumberStyles.HexNumber);
                                        SymbolTables[i] = cur;
                                    }
                                    reader.BaseStream.Position = curpos;
                                }
                                //now let's read relocation info
                                var RAWOFRELOC = rvaToOff(sectionHeaders[6].VirtualAddress);
                                var curpsss = reader.BaseStream.Position;
                                reader.BaseStream.Seek(RAWOFRELOC, SeekOrigin.Begin);
                                var relocsize = sectionHeaders[6].SizeOfRawData;
                                if (showReloc)
                                {
                                    while (relocsize != 0)
                                    {
                                        var cur = new BaseRelocationBlock();
                                        var pageRva = cur.PageRVA = UInt32.Parse(
                                            Convert.ToHexString(reverser(reader.ReadBytes(4))),
                                            System.Globalization.NumberStyles.HexNumber);
                                        var BlockSize = cur.BlockSize = UInt32.Parse(
                                            Convert.ToHexString(reverser(reader.ReadBytes(4))),
                                            System.Globalization.NumberStyles.HexNumber);
                                        if (BlockSize == 0)
                                        {
                                            break;
                                        }
                                        ushort[] relocentries =
                                            new ushort[(BlockSize - 8) / 2];
                                        for (int i = 0; i < relocentries.Length; i++)
                                        {
                                            relocentries[i] =
                                                UInt16.Parse(Convert.ToHexString(reverser(reader.ReadBytes(2))),
                                                    System.Globalization.NumberStyles.HexNumber);
                                        }
                                        cur.entries = relocentries;
                                        relocsize -= BlockSize;
                                        Console.WriteLine("Virtual Address: " + cur.PageRVA + " Chunk Size: " +
                                                          cur.BlockSize + " Number of fixups: " + cur.entries.Length);
                                        for (int j = 0; j < cur.entries.Length; j++)
                                        {
                                            Console.Write("reloc: " + j + " offset: " + (cur.entries[j] & 0xFFF));
                                            var type = (cur.entries[j] & 0xF000) >> 12;
                                            switch (type)
                                            {
                                                case 0:
                                                    Console.WriteLine(" BASED_ABSOLUTE");
                                                    break;
                                                case 1:
                                                    Console.WriteLine(" BASED_HIGH");
                                                    break;
                                                case 2:
                                                    Console.WriteLine(" BASED_LOW");
                                                    break;
                                                case 3:
                                                    Console.WriteLine(" BASED_HIGHLOW");
                                                    break;
                                                case 4:
                                                    Console.WriteLine(" BASED_HIGHADJ");
                                                    break;
                                                case 5:
                                                    Console.WriteLine(" BASED_ARM_MOV32");
                                                    break;
                                                case 7:
                                                    Console.WriteLine(" BASED_RISCV_LOW12I");
                                                    break;
                                                case 8:
                                                    Console.WriteLine(" BASED_RISCV_LOW12S");
                                                    break;
                                                case 9:
                                                    Console.WriteLine(" BASED_MIPS_JMPADDR16");
                                                    break;
                                                case 10:
                                                    Console.WriteLine(" BASED_DIR64");
                                                    break;
                                            }
                                        }
                                    }
                                }
                                //here well read export and import tables
                                //Export DIR INFO //TODO: ADD EXPORT INFO DIR
                                //let's start with export dir
                                uint exportRAW = 0;
                                if (if32)
                                {
                                    exportRAW = rvaToOff(optionalHeader32._dataDericotry[0].VirtualAddress);
                                }
                                else
                                {
                                    exportRAW = rvaToOff(optionalHeader64._dataDericotry[0].VirtualAddress);
                                }
                                var curposs = reader.BaseStream.Position;
                                reader.BaseStream.Seek(exportRAW, SeekOrigin.Begin);
                                var ExportDir = new ExportDirectory();
                                ExportDir.Characteristics = UInt32.Parse(Convert.ToHexString(reverser(reader.ReadBytes(4))), System.Globalization.NumberStyles.HexNumber);
                                ExportDir.TimeDateStamp = UInt32.Parse(Convert.ToHexString(reverser(reader.ReadBytes(4))), System.Globalization.NumberStyles.HexNumber);
                                ExportDir.MajorVersion = UInt16.Parse(Convert.ToHexString(reverser(reader.ReadBytes(2))), System.Globalization.NumberStyles.HexNumber);
                                ExportDir.MinorVersion = UInt16.Parse(Convert.ToHexString(reverser(reader.ReadBytes(2))), System.Globalization.NumberStyles.HexNumber);
                                ExportDir.Name = UInt32.Parse(Convert.ToHexString(reverser(reader.ReadBytes(4))), System.Globalization.NumberStyles.HexNumber);
                                ExportDir.Base = UInt32.Parse(Convert.ToHexString(reverser(reader.ReadBytes(4))), System.Globalization.NumberStyles.HexNumber);
                                ExportDir.NumberOfFunctions = UInt32.Parse(Convert.ToHexString(reverser(reader.ReadBytes(4))), System.Globalization.NumberStyles.HexNumber);
                                ExportDir.NumberOfNames = UInt32.Parse(Convert.ToHexString(reverser(reader.ReadBytes(4))), System.Globalization.NumberStyles.HexNumber);
                                ExportDir.AddressOfFunctions = UInt32.Parse(Convert.ToHexString(reverser(reader.ReadBytes(4))), System.Globalization.NumberStyles.HexNumber);
                                ExportDir.AddressOfNames = UInt32.Parse(Convert.ToHexString(reverser(reader.ReadBytes(4))), System.Globalization.NumberStyles.HexNumber);
                                ExportDir.AddressOfNameOrdinals = ExportDir.AddressOfNames = UInt32.Parse(Convert.ToHexString(reverser(reader.ReadBytes(4))), System.Globalization.NumberStyles.HexNumber);
                                reader.BaseStream.Position = curposs;
                                //IMPORT DIR INFO //TODO: ADD IMPORT INFO DIR
                            }
                            showFinalOutput();
                        }
                        else
                        {
                            Console.WriteLine("No, it's not a PE file, bye bye");
                            Environment.Exit(0);
                        }
                    }
                }
                else
                {
                    Console.WriteLine("File is empty, lol");
                }
                }

            else
            {
                Console.WriteLine("There is no such file");
            }
                        
        
        }

        static bool checkExecutable(byte[] arr)
        {
            if (arr[0] == 0x4d && arr[1] == 0x5a)
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        static bool checkSignature(byte[] arr)
        {
            if (arr[0] == 0x50 && arr[1] == 0x45 && arr[2] == 0x00 && arr[3] == 0x00)
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        static void setArchType(byte[] arr)
        {
            if (Convert.ToHexString(arr) == "8664")
            {
                Arch += "AMD64: x86-64";
            } else if (Convert.ToHexString(arr) == "014C")
            {
                Arch += "x32";
            } else if (Convert.ToHexString(arr) == "0200")
            {
                Arch += "Intel Itanuim x64";
            }
        }

        static void setMagic(byte[] arr)
        {
            if (Convert.ToHexString(arr) == "010B")
            {
                Bitnost += "x32 (x86) executable";
            } else if (Convert.ToHexString(arr) == "020B")
            {
                Bitnost += "x64 executable";
            } else if (Convert.ToHexString(arr) == "0107")
            {
                Bitnost += "ROM image";
            }
        }

        static void showFinalOutput()
        {
            Console.WriteLine("FileName: " + fileName);
            Console.WriteLine(Arch);
            Console.WriteLine(Bitnost);
            if (showHeaderInfo)
            {
                calcFlags();
                if (if32)
                {
                    Console.WriteLine("Start address: " + (optionalHeader32.AddressOfEntryPoint + optionalHeader32.ImageBase));
                }
                else
                {
                    Console.WriteLine("Start address: " + (optionalHeader64.ImageBase + optionalHeader64.AddressOfEntryPoint));
                }
            }

            if (showSymbolsInfo)
            {
                calcSymbols();
            }
            if (showSections)
            {
                if (sectionHeaders != null)
                {
                    Console.WriteLine("Sections:");
                    for (int i = 0; i < sectionHeaders.Length; i++)
                    {
                        Console.WriteLine("Section id: " + i + ", Section name: " +
                                          Encoding.Default.GetString(sectionHeaders[i].Name) +
                                          ", Section size: " + sectionHeaders[i].VirtualSize +
                                          ", VMA: " + sectionHeaders[i].VirtualAddress +
                                          ", LMA: " + sectionHeaders[i].VirtualAddress + ", File off: " + sectionHeaders[i].PointerToRawData + ", " +
                                          calcChars(sectionHeaders[i].Characteristics));
                    }
                }
            }

            if (showImportExportInfo)
            {
                calcImportExportInfo();
            }
        }

        static void calcFlags()
        {
            var kek = fileheader.Characteristics;
            bool RELOCS_STRIPPED = (kek & 0x0001) != 0;
            bool EXECUTABLE_IMAGE = (kek & 0x0002) != 0;
            bool LINE_NUMS_STRIPPED = (kek & 0x0004) != 0;
            bool LOCAL_SYMS_STRIPPED = (kek & 0x0008) != 0;
            bool AGGRESSIVE_WS_TRIM = (kek & 0x0010) != 0;
            bool LARGE_ADDRESS_AWARE = (kek & 0x0020) != 0;
            bool BYTES_REVERSED_LO = (kek & 0x0080) != 0;
            bool _32BIT_MACHINE = (kek & 0x0100) != 0;
            bool DEBUG_STRIPPED = (kek & 0x0200) != 0;
            bool REMOVABLE_RUN_FROM_SWAP = (kek & 0x0400) != 0;
            bool NET_RUN_FROM_SWAP = (kek & 0x0800) != 0;
            bool SYSTEM = (kek & 0x1000) != 0;
            bool DLL = (kek & 0x2000) != 0;
            bool SYSTEM_ONLY = (kek & 0x4000) != 0;
            bool BYTES_REVERSED_HI = (kek & 0x8000) != 0;
            var ans = "FLAGS: ";
            if (RELOCS_STRIPPED)
            {
                ans += "RELOCS_STRIPPED, ";
            }

            if (EXECUTABLE_IMAGE)
            {
                ans += "EXECUTABLE_IMAGE, ";
            }

            if (LINE_NUMS_STRIPPED)
            {
                ans += "LINE_NUMS_STRIPPED, ";
            }

            if (LOCAL_SYMS_STRIPPED)
            {
                ans += "LOCAL_SYMS_STRIPPED, ";
            }

            if (_32BIT_MACHINE)
            {
                ans += "32BIT_MACHINE, ";
            }

            if (AGGRESSIVE_WS_TRIM)
            {
                ans += "AGGRESSIVE_WS_TRIM, ";
            }

            if (LARGE_ADDRESS_AWARE)
            {
                ans += "LARGE_ADDRESS_AWARE, ";
            }

            if (BYTES_REVERSED_LO)
            {
                ans += "BYTES_REVERSED_LO, ";
            }

            if (BYTES_REVERSED_HI)
            {
                ans += "BYTES_REVERSED_HI, ";
            }

            if (DEBUG_STRIPPED)
            {
                ans += "DEBUG_STRIPPED, ";
            }

            if (REMOVABLE_RUN_FROM_SWAP)
            {
                ans += "REMOVABLE_RUN_FROM_SWAP, ";
            }

            if (NET_RUN_FROM_SWAP)
            {
                ans += "NET_RUN_FROM_SWAP, ";
            }

            if (SYSTEM)
            {
                ans += "SYSTEM, ";
            }

            if (DLL)
            {
                ans += "DLL, ";
            }

            if (SYSTEM_ONLY)
            {
                ans += "SYSTEM_ONLY, ";
            }

            ans = ans.Substring(0, ans.Length - 2);
            Console.WriteLine(ans);
        }

        static string calcChars(uint lol)
        {
            var kek = lol;
            bool ifcode = (kek & 0x20) != 0;
            bool ifinitdata = (kek & 0x40) != 0;
            bool ifuninitdata = (kek & 0x80) != 0;
            bool ifdicardable = (kek & 0x02000000) != 0;
            bool ifnotcached = (kek & 0x04000000) != 0;
            bool ifnotpaged = (kek & 0x08000000) != 0;
            bool ifmemshared = (kek & 0x10000000) != 0;
            bool ifexecute = (kek & 0x20000000) != 0;
            bool ifread = (kek & 0x40000000) != 0;
            bool ifwrite = (kek & 0x80000000) != 0;
            //TODO: add data bounderies (align)
            String res = "Section characteristics: ";
            if (ifcode)
            {
                res += "Code section, ";
            }

            if (ifinitdata)
            {
                res += "Initialized data section, ";
            }

            if (ifuninitdata)
            {
                res += "Uninitialized data section, ";
            }

            if (ifdicardable)
            {
                res += "DISCARDABLE, ";
            }

            if (ifnotcached)
            {
                res += "NOT_CACHED, ";
            }

            if (ifnotpaged)
            {
                res += "NOT_PAGED, ";
            }

            if (ifmemshared)
            {
                res += "MEM_SHARED, ";
            }

            if (ifexecute)
            {
                res += "EXECUTE, ";
            }

            if (ifread)
            {
                res += "READ, ";
            }

            if (ifwrite)
            {
                res += "WRITE, ";
            }

            if (res[res.Length - 1] == ',')
            {
                res.Substring(0, res.Length - 2);
            }

            return res;
        }

        static byte[] reverser(byte[] arr)
        {
            Array.Reverse(arr);
            return arr;
        }

        static void calcSymbols()
        {
            //TODO:FIX SOME ISSUES WITH CALCULATING check mircrosoft website
            if (!hassymbols)
            {
                Console.WriteLine("SYMBOL TABLE: No symbols");
            }
            else
            {
                Console.WriteLine("Symbol table: ");
                for (int i = 0; i < SymbolTables.Length; i++)
                {
                    var cur = SymbolTables[i];
                    Console.WriteLine("Name: " + Encoding.Default.GetString(cur.Name) + ", Value: " + cur.Value + 
                                      ", Section Number: " + cur.SectionNumber + ", Type: " + cur.Type + 
                                      ", Storage Class: " + cur.StorageClass + ", NumberOfAuxSymbols: " + cur.NumberOfAuxSymbols);
                }
            }
        }
        static void calcImportExportInfo()
        {
            //TODO: ADD IMPORT EXPORT INFO CALCULATION
        }
        
        ///here are methods for recalculating RAW offset
        static int defSection(uint rva)
        {
            for (int i = 0; i < sectionHeaders.Length; ++i)
            {
                uint start = sectionHeaders[i].VirtualAddress;
                uint end = start + ALIGN_UP(sectionHeaders[i].VirtualSize, alingment);

                if(rva >= start && rva < end)
                    return i;
            }
            return -1;
        }

        static uint ALIGN_UP(uint x, uint align)
        {
            if ((x & (align - 1)) == 1)
            {
                return ALIGN_DOWN(x, align) + align;
            }
            else
            {
                return x;
            }
            
        }

        static uint ALIGN_DOWN(uint x, uint align)
        {
            return (x & ~(align - 1));
        } 
        static uint rvaToOff(uint rva)
        {
            long indexSection = defSection(rva);
            if(indexSection != -1)
                return rva - sectionHeaders[indexSection].VirtualAddress + sectionHeaders[indexSection].PointerToRawData;
            else
                return 0;
        }
        
        //rvaToRAW methods ended

        /* do I need this code?
        static void calcBaseRelocation()
        {
            Console.WriteLine("Base relocations(.reloc): ");
            for (int i = 0; i < baseRelocationBlocks.Count; i++)
            {
                var cur = baseRelocationBlocks[i];
                Console.WriteLine("Virtual Address: " + cur.PageRVA + " Chunk Size: " + cur.BlockSize + " Number of fixups: " + cur.entries.Length);
                for (int j = 0; j < cur.entries.Length; j++)
                {
                    Console.Write("reloc: " + j + "offset: ");
                    var type = (cur.entries[j] & 1111000000000000);
                    Console.Write(cur.entries[j] & 0000111111111111);
                    switch (type)
                    {
                        case 0: Console.WriteLine(" BASED_ABSOLUTE");
                            break;
                        case 1: Console.WriteLine(" BASED_HIGH");
                            break;
                        case 2: Console.WriteLine(" BASED_LOW");
                            break;
                        case 3: Console.WriteLine(" BASED_HIGHLOW");
                            break;
                        case 4: Console.WriteLine(" BASED_HIGHADJ");
                            break;
                        case 5: Console.WriteLine(" BASED_ARM_MOV32");
                            break;
                        case 7: Console.WriteLine(" BASED_RISCV_LOW12I");
                            break;
                        case 8: Console.WriteLine(" BASED_RISCV_LOW12S");
                            break;
                        case 9: Console.WriteLine(" BASED_MIPS_JMPADDR16");
                            break;
                        case 10: Console.WriteLine(" BASED_DIR64");
                            break;
                    }
                    break; //debug
                }

                break; //debug
                
            }
            */
            
        }
    

    class FileHeader
    {
        public ushort Machine; //Process arch
        public ushort NumberOfSections; //Number of sections
        public uint TimeDateStamp; //Programm creation date and time
        public uint PointerToSymbolTable; 
        public uint NumberOfSymbols;//Number of symbols per table
        public ushort SizeOfOptionalHeader;
        public ushort Characteristics;
    }
    

    class OptionalHeader32
    {
        public ushort Magic; 
        public byte MajorLinkerVersion; 
        public byte MinorLinkerVersion; 
        public uint SizeOfCode; 
        public uint SizeOfInitializedData;
        public uint SizeOfUninitializedData;
        public uint AddressOfEntryPoint;
        public uint BaseOfCode;
        public uint BaseOfData;
        public uint ImageBase; //not same
        public uint SectionAlignment;
        public uint FileAlignment;
        public ushort  MajorOperatingSystemVersion;
        public ushort  MinorOperatingSystemVersion;
        public ushort  MajorImageVersion;
        public ushort  MinorImageVersion;
        public ushort  MajorSubsystemVersion;
        public ushort  MinorSubsystemVersion;
        public uint Win32VersionValue;
        public uint SizeOfImage;
        public uint SizeOfHeaders;
        public uint CheckSum;
        public ushort  Subsystem;
        public ushort  DllCharacteristics;
        public uint SizeOfStackReserve; //not same
        public uint SizeOfStackCommit; //not same
        public uint SizeOfHeapReserve; //not same
        public uint SizeOfHeapCommit; //not same
        public uint LoaderFlags;
        public uint NumberOfRvaAndSizes;
        public DataDericotry[] _dataDericotry;
    }

    class OptionalHeader64
    {
        public ushort Magic; 
        public byte MajorLinkerVersion;
        public byte MinorLinkerVersion; 
        public uint SizeOfCode; 
        public uint SizeOfInitializedData;
        public uint SizeOfUninitializedData;
        public uint AddressOfEntryPoint;
        public uint BaseOfCode;
        public UInt64 ImageBase; //not same
        public uint SectionAlignment;
        public uint FileAlignment;
        public ushort  MajorOperatingSystemVersion;
        public ushort  MinorOperatingSystemVersion;
        public ushort  MajorImageVersion;
        public ushort  MinorImageVersion;
        public ushort  MajorSubsystemVersion;
        public ushort  MinorSubsystemVersion;
        public uint Win32VersionValue;
        public uint SizeOfImage;
        public uint SizeOfHeaders;
        public uint CheckSum;
        public ushort  Subsystem;
        public ushort  DllCharacteristics;
        public UInt64 SizeOfStackReserve; //not same
        public UInt64 SizeOfStackCommit; //not same
        public UInt64 SizeOfHeapReserve; //not same
        public UInt64 SizeOfHeapCommit; //not same
        public uint LoaderFlags;
        public uint NumberOfRvaAndSizes;
        public DataDericotry[] _dataDericotry;
    }

    class DataDericotry
    {
        public uint VirtualAddress;
        public uint Size;
    }

    class SectionHeader
    {
        public byte[] Name;
        public uint PhysicalAddress;
        public uint VirtualSize; //same as prev (do not read twice for that)
        public uint VirtualAddress;
        public uint SizeOfRawData;
        public uint PointerToRawData;
        public uint PointerToRelocations;
        public uint PointerToLinenumbers;
        public ushort NumberOfRelocations;
        public ushort NumberOfLinenumbers;
        public uint Characteristics;

    }

    class SymbolTable
    {
        public byte[] Name;
        public uint Value;
        public short SectionNumber;
        public ushort Type;
        public byte StorageClass;
        public byte NumberOfAuxSymbols;
    }

    class BaseRelocationBlock
    {
        public uint PageRVA;
        public uint BlockSize;
        public ushort[] entries;
    }

    class ExportDirectory
    {
        public uint Characteristics;
        public uint TimeDateStamp;
        public ushort MajorVersion;
        public ushort MinorVersion;
        public uint Name;
        public uint Base;
        public uint NumberOfFunctions;
        public uint NumberOfNames;
        public uint AddressOfFunctions;
        public uint AddressOfNames;
        public uint AddressOfNameOrdinals;
    }

    class SomethingWentWrongException : Exception
    {
        public SomethingWentWrongException()
        {
            Console.WriteLine("SomethingWentWrongException");
        }
    }
}