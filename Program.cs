using System;
using System.IO;
using System.Linq;
using System.Reflection.PortableExecutable;
using System.Runtime.CompilerServices;
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
        
        
        
        
        
        public static bool if32 = false;
        public static String fileName = "";
        public static String Arch = "architecture: ";
        public static String Bitnost = "file type: ";
        static void Main(string[] args)
        {
            //string kek = Console.ReadLine();
            //Console.WriteLine(kek);
            Console.WriteLine(UInt32.Parse(Convert.ToHexString(reverser(new byte[]{0x10, 0x00, 0x00, 0x00})), System.Globalization.NumberStyles.HexNumber));
            fileName = "77.exe";
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
                            //debug Console.WriteLine("Yes, it's a PE file");
                            var e_lfanew = new byte[4]; //here we read our pe offest it's a PE offset
                            reader.BaseStream.Seek(60, SeekOrigin.Begin);
                            reader.Read(e_lfanew, 0, 4);
                            Array.Reverse(e_lfanew);
                            long offset = Int32.Parse(Convert.ToHexString(e_lfanew),
                                System.Globalization.NumberStyles.HexNumber);
                            //debug Console.WriteLine("PE offset in dec: " + offset); 
                            
                            //now let's double check that it's a PE file by checking signature
                            
                            var signature = new byte[4];
                            reader.BaseStream.Seek(440, SeekOrigin.Begin);
                            reader.Read(signature, 0, 4);
                            if (checkSignature(signature))
                            {
                                //debug Console.WriteLine("Double check is done, it's a pe file");
                                //here we fill our header file
                                var fileheader = new FileHeader(); //let's create file header
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
                                var sizeofoptheader = new byte[2];
                                reader.BaseStream.Seek(12, SeekOrigin.Current);
                                reader.Read(sizeofoptheader, 0, 2);
                                Array.Reverse(sizeofoptheader);
                                //debug Console.WriteLine(Convert.ToHexString(sizeofoptheader));
                                fileheader.SizeOfOptionalHeader = UInt16.Parse(Convert.ToHexString(sizeofoptheader),
                                    System.Globalization.NumberStyles.HexNumber);
                                //debug Console.WriteLine(fileheader.SizeOfOptionalHeader);
                                //characteristics
                                var chara = new byte[2];
                                reader.Read(chara, 0, 2);
                                Array.Reverse(chara);
                                fileheader.Characteristics = UInt16.Parse(Convert.ToHexString(sizeofoptheader),
                                    System.Globalization.NumberStyles.HexNumber);
                                
                                //now well be filling out OPTIONAL HEADER
                                
                                //var optionalHeader = new OptionalHeader32();
                                var magic = reader.ReadBytes(2);
                                Array.Reverse(magic);
                                setMagic(magic);
                                var optionalHeader64 = new OptionalHeader64();
                                var optionalHeader32 = new OptionalHeader32();
                                Console.WriteLine("Reader cur pos: " + reader.BaseStream.Position);
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
                                Console.WriteLine("Reader cur pos: " + reader.BaseStream.Position);
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
                                Console.WriteLine("Reader cur pos: " + reader.BaseStream.Position);
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
                                Console.WriteLine(n);

                                DataDericotry[] dat = new DataDericotry[n];
                                for (int i = 0; i < n; i++)
                                {
                                    uint va = UInt32.Parse(Convert.ToHexString(reverser(reader.ReadBytes(4))), System.Globalization.NumberStyles.HexNumber);
                                    uint sz = UInt32.Parse(Convert.ToHexString(reverser(reader.ReadBytes(4))), System.Globalization.NumberStyles.HexNumber);
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
                                Console.WriteLine("Test subsystem value: " + optionalHeader64.Subsystem);

                            }
                            showFinalOutput();
                        }
                        else
                        {
                            Console.WriteLine("No, it's not a PE file, bye bye");
                            System.Environment.Exit(0);
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
        }

        static byte[] reverser(byte[] arr)
        {
            Array.Reverse(arr);
            return arr;
        }
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

    class SomethingWentWrongException : Exception
    {
        public SomethingWentWrongException()
        {
            Console.WriteLine("SomethingWentWrongException");
        }
    }
}