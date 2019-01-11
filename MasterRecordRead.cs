using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Threading;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.WindowsRuntime;

namespace ComeAndGet
{

    public class PinvokeWin32
    {
        #region DllImports and Constants

        public const UInt32 GENERIC_READ = 0x80000000;
        public const UInt32 GENERIC_WRITE = 0x40000000;
        public const UInt32 FILE_SHARE_READ = 0x00000001;
        public const UInt32 FILE_SHARE_WRITE = 0x00000002;
        public const UInt32 FILE_ATTRIBUTE_DIRECTORY = 0x00000010;
        public const UInt32 OPEN_EXISTING = 3;
        public const UInt32 FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
        public const Int32 INVALID_HANDLE_VALUE = -1;
        public const UInt32 FSCTL_QUERY_USN_JOURNAL = 0x000900f4;
        public const UInt32 FSCTL_ENUM_USN_DATA = 0x000900b3;
        public const UInt32 FSCTL_CREATE_USN_JOURNAL = 0x000900e7;
        public const UInt32 CREATE_ALWAYS = 0x00000002;
        public const UInt32 FILE_FLAG_SEQUENTIAL_SCAN = 0x08000000;

        private IntPtr _changeJournalRootHandle;
        private Dictionary<ulong, FileNameAndFrn> _directories = new Dictionary<ulong, FileNameAndFrn> ( );
        private string _drive = "";
        public string Drive
        {
            get { return _drive; }
            set { _drive = value; }
        }
        private Dictionary<UInt64, FileNameAndFrn> directories_ = new Dictionary<ulong, FileNameAndFrn> ( );
        public Dictionary<UInt64, FileNameAndFrn> directories
        {
            get { return directories_; }
            set { directories_ = value; }
        }

        [DllImport ( "kernel32.dll", SetLastError = true )]
        public static extern IntPtr CreateFile ( string lpFileName, uint dwDesiredAccess,
                                                  uint dwShareMode, IntPtr lpSecurityAttributes,
                                                  uint dwCreationDisposition, uint dwFlagsAndAttributes,
                                                  IntPtr hTemplateFile );

        [DllImport ( "kernel32.dll", SetLastError = true )]
        [return: MarshalAs ( UnmanagedType.Bool )]
        public static extern bool GetFileInformationByHandle ( IntPtr hFile,
                                                                     out BY_HANDLE_FILE_INFORMATION lpFileInformation );

        [DllImport ( "kernel32.dll", SetLastError = true )]
        [return: MarshalAs ( UnmanagedType.Bool )]
        public static extern bool CloseHandle ( IntPtr hObject );

        [DllImport ( "kernel32.dll", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Auto )]
        [return: MarshalAs ( UnmanagedType.Bool )]
        public static extern bool DeviceIoControl ( IntPtr hDevice,
                                                      UInt32 dwIoControlCode,
                                                      IntPtr lpInBuffer, Int32 nInBufferSize,
                                                      out USN_JOURNAL_DATA lpOutBuffer, Int32 nOutBufferSize,
                                                      out uint lpBytesReturned, IntPtr lpOverlapped );

        [DllImport ( "kernel32.dll", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Auto )]
        [return: MarshalAs ( UnmanagedType.Bool )]
        public static extern bool DeviceIoControl ( IntPtr hDevice,
                                                      UInt32 dwIoControlCode,
                                                      IntPtr lpInBuffer, Int32 nInBufferSize,
                                                      IntPtr lpOutBuffer, Int32 nOutBufferSize,
                                                      out uint lpBytesReturned, IntPtr lpOverlapped );

        [DllImport ( "kernel32.dll" )]
        public static extern void ZeroMemory ( IntPtr ptr, Int32 size );

        [DllImport ( "kernel32.dll" )]
        static extern bool ReadFile ( IntPtr hFile, byte[ ] lpBuffer,
           uint nNumberOfBytesToRead, out uint lpNumberOfBytesRead, IntPtr lpOverlapped );

        public partial class NativeMethods
        {
            /// Return Type: DWORD->unsigned int
            [System.Runtime.InteropServices.DllImportAttribute ( "kernel32.dll", EntryPoint = "GetLastError" )]
            public static extern uint GetLastError ( );
        }

        [DllImport ( "kernel32.dll", SetLastError = true )]
        static extern bool ReadFile ( IntPtr hFile, [Out] byte[ ] lpBuffer, uint nNumberOfBytesToRead,    // ReadFile
             out uint lpNumberOfBytesRead, [In] ref System.Threading.NativeOverlapped lpOverlapped );
        // or
        [DllImport ( "kernel32.dll", SetLastError = true )]
        private unsafe static extern bool ReadFile (                                       // ReadFile
            int hFile,                        // handle to file
            byte[ ] lpBuffer,                // data buffer
            int nNumberOfBytesToRead,        // number of bytes to read
            ref int lpNumberOfBytesRead,    // number of bytes read
            int* ptr
            // 
            // ref OVERLAPPED lpOverlapped        // overlapped buffer
            );

        [StructLayout ( LayoutKind.Sequential, Pack = 1 )]
        public struct BY_HANDLE_FILE_INFORMATION
        {
            public uint FileAttributes;
            public FILETIME CreationTime;
            public FILETIME LastAccessTime;
            public FILETIME LastWriteTime;
            public uint VolumeSerialNumber;
            public uint FileSizeHigh;
            public uint FileSizeLow;
            public uint NumberOfLinks;
            public uint FileIndexHigh;
            public uint FileIndexLow;
        }

        //*****************
        [StructLayout ( LayoutKind.Sequential, Pack = 1 )]
        public struct _SECURITY_ATTRIBUTES
        {
            public UInt32 nLength;
            public IntPtr lpSecurityDescriptor;
            public bool bInheritHandle;
        }
        //***************
        [DllImport ( "kernel32.dll" )]
        static extern bool ReadFileScatter ( IntPtr hFile, FILE_SEGMENT_ELEMENT[ ]            // ReadFileScatter
           aSegementArray, uint nNumberOfBytesToRead, IntPtr lpReserved,
           [In] ref System.Threading.NativeOverlapped lpOverlapped );

        [DllImport ( "kernel32.dll", SetLastError = true )]
        static extern unsafe int ReadFileScatter ( IntPtr hFile,                               // // ReadFileScatter
          FILE_SEGMENT_ELEMENT* aSegmentArray, int nNumberOfBytesToRead,
          IntPtr lpReserved, NativeOverlapped* lpOverlapped );

        [StructLayout ( LayoutKind.Explicit, Size = 8 )]
        internal struct FILE_SEGMENT_ELEMENT
        {
            [FieldOffset ( 0 )]
            public IntPtr Buffer;
            [FieldOffset ( 0 )]
            public UInt64 Alignment;
        }

        [StructLayout ( LayoutKind.Explicit, Size = 20 )]
        public struct OVERLAPPED
        {
            [FieldOffset ( 0 )]
            public uint Internal;
            [FieldOffset ( 4 )]
            public uint InternalHigh;
            [FieldOffset ( 8 )]
            public uint Offset;
            [FieldOffset ( 12 )]
            public uint OffsetHigh;
            [FieldOffset ( 8 )]
            public IntPtr Pointer;
            [FieldOffset ( 16 )]
            public IntPtr hEvent;
        }

        [StructLayout ( LayoutKind.Sequential, Pack = 1 )]
        public struct FILETIME
        {
            public uint DateTimeLow;
            public uint DateTimeHigh;
        }

        [StructLayout ( LayoutKind.Sequential, Pack = 1 )]
        public struct USN_JOURNAL_DATA
        {
            public UInt64 UsnJournalID;
            public Int64 FirstUsn;
            public Int64 NextUsn;
            public Int64 LowestValidUsn;
            public Int64 MaxUsn;
            public UInt64 MaximumSize;
            public UInt64 AllocationDelta;
        }

        [StructLayout ( LayoutKind.Sequential, Pack = 1 )]
        public struct MFT_ENUM_DATA
        {
            public UInt64 StartFileReferenceNumber;
            public Int64 LowUsn;
            public Int64 HighUsn;
        }

        [StructLayout ( LayoutKind.Sequential, Pack = 1 )]
        public struct CREATE_USN_JOURNAL_DATA
        {
            public UInt64 MaximumSize;
            public UInt64 AllocationDelta;
        }

        public void MainWWWW ( string ext )
        {
            // ext is in the form ".png" or ".dll"
            Dictionary<ulong, FileNameAndFrn> _directories = new Dictionary<ulong, FileNameAndFrn> ( );
            PinvokeWin32 mft = new PinvokeWin32 ( );
            mft.Drive = "F:";
            mft.EnumerateVolume ( out Dictionary<UInt64, FileNameAndFrn>  result, new string[ ] { ext } );

            foreach ( KeyValuePair<UInt64, FileNameAndFrn> entry in result )
            {
                FileNameAndFrn file = ( FileNameAndFrn )entry.Value;
                Console.WriteLine ( file.Name );
            }
            Console.WriteLine ( "DONE" );
            Console.ReadKey ( );
        }                            // MainWWWW

        public void EnumerateVolume (out Dictionary<ulong, FileNameAndFrn> files, string[ ] fileExtensions)   // UInt64
        {
            files = new Dictionary<ulong, FileNameAndFrn> ( );
            IntPtr medBuffer = IntPtr.Zero;
            try
            {
                GetRootFrnEntry ( );
                GetRootHandle ( );
                CreateChangeJournal ( );
                SetupMFT_Enum_DataBuffer ( ref medBuffer );
                EnumerateFiles ( medBuffer, ref files, fileExtensions );
            }

            catch ( Exception e )
            {
                Console.WriteLine ( e.Message, e.StackTrace  );
                Exception innerException = e.InnerException;
                while ( innerException != null )
                {
                    Console.WriteLine ( innerException.Message, innerException );
                    innerException = innerException.InnerException;
                }
                throw new ApplicationException ( "Error in EnumerateVolume()", e );
            }
            finally
            {
                if ( _changeJournalRootHandle.ToInt32 ( ) != PinvokeWin32.INVALID_HANDLE_VALUE )
                {
                    PinvokeWin32.CloseHandle ( _changeJournalRootHandle );
                }
                if ( medBuffer != IntPtr.Zero )
                {
                    Marshal.FreeHGlobal ( medBuffer );
                }
            }
        }                                               // EnumerateVolume

        unsafe private void SetupMFT_Enum_DataBuffer ( ref IntPtr medBuffer )
        {
            PinvokeWin32.USN_JOURNAL_DATA ujd = new PinvokeWin32.USN_JOURNAL_DATA ( );

            bool bOk = PinvokeWin32.DeviceIoControl ( _changeJournalRootHandle,                           // Handle to drive   
                PinvokeWin32.FSCTL_QUERY_USN_JOURNAL,   // IO Control Code   
                IntPtr.Zero,                            // In Buffer   
                0,                                      // In Buffer Size   
                out ujd,                                // Out Buffer   
                sizeof ( PinvokeWin32.USN_JOURNAL_DATA ),  // Size Of Out Buffer   
                out uint bytesReturned,                   // Bytes Returned   
                IntPtr.Zero );                            // lpOverlapped   
            if ( bOk )
            {
                PinvokeWin32.MFT_ENUM_DATA med;
                med.StartFileReferenceNumber = 0;
                med.LowUsn = 0;
                med.HighUsn = ujd.NextUsn;
                int sizeMftEnumData = Marshal.SizeOf ( med );
                medBuffer = Marshal.AllocHGlobal ( sizeMftEnumData );
                PinvokeWin32.ZeroMemory ( medBuffer, sizeMftEnumData );
                Marshal.StructureToPtr ( med, medBuffer, true );
            }
            else
            {
                throw new IOException ( "DeviceIoControl() returned false", new Win32Exception ( Marshal.GetLastWin32Error ( ) ) );
            }
        }                                               // SetupMFT_Enum_DataBuffer        

        private void GetRootFrnEntry ( )
        {
            string driveRoot = string.Concat ( "\\\\.\\", _drive );
            driveRoot = string.Concat ( driveRoot, Path.DirectorySeparatorChar );
            IntPtr hRoot = PinvokeWin32.CreateFile ( driveRoot, 0,
                PinvokeWin32.FILE_SHARE_READ | PinvokeWin32.FILE_SHARE_WRITE,
                IntPtr.Zero,
                PinvokeWin32.OPEN_EXISTING,
                PinvokeWin32.FILE_FLAG_BACKUP_SEMANTICS,
                IntPtr.Zero );

            if ( hRoot.ToInt32 ( ) != PinvokeWin32.INVALID_HANDLE_VALUE )
            {
                PinvokeWin32.BY_HANDLE_FILE_INFORMATION fi = new PinvokeWin32.BY_HANDLE_FILE_INFORMATION ( );
                bool bRtn = PinvokeWin32.GetFileInformationByHandle ( hRoot, out fi );
                if ( bRtn )
                {
                    UInt64 fileIndexHigh = ( UInt64 )fi.FileIndexHigh;
                    UInt64 indexRoot = ( fileIndexHigh << 32 ) | fi.FileIndexLow;

                    FileNameAndFrn f = new FileNameAndFrn ( driveRoot, 0 );
                    directories.Add ( indexRoot, f );
                }
                else
                {
                    throw new IOException ( "GetFileInformationbyHandle() returned invalid handle",
                        new Win32Exception ( Marshal.GetLastWin32Error ( ) ) );
                }
                PinvokeWin32.CloseHandle ( hRoot );
            }
            else
            {
                throw new IOException ( "Unable to get root frn entry", new Win32Exception ( Marshal.GetLastWin32Error ( ) ) );
            }
        }                                               // GetRootFrnEntry

        private void GetRootHandle ( )
        {
            string vol = string.Concat ( "\\\\.\\", _drive );
            _changeJournalRootHandle = PinvokeWin32.CreateFile ( vol,
                 PinvokeWin32.GENERIC_READ | PinvokeWin32.GENERIC_WRITE,
                 PinvokeWin32.FILE_SHARE_READ | PinvokeWin32.FILE_SHARE_WRITE,
                 IntPtr.Zero,
                 PinvokeWin32.OPEN_EXISTING,
                 0,
                 IntPtr.Zero );
            if ( _changeJournalRootHandle.ToInt32 ( ) == PinvokeWin32.INVALID_HANDLE_VALUE )
            {
                throw new IOException ( "CreateFile() returned invalid handle",
                    new Win32Exception ( Marshal.GetLastWin32Error ( ) ) );
            }
        }                                               // GetRootHandle

        private void GetRootHandleRead ( string drive )
        {  // my modification
            string vol = string.Concat ( "\\\\.\\", drive );
            _changeJournalRootHandle = PinvokeWin32.CreateFile ( vol,
                 PinvokeWin32.GENERIC_READ,
                 PinvokeWin32.FILE_SHARE_READ,
                 IntPtr.Zero,
                 PinvokeWin32.OPEN_EXISTING,
                 0,
                 IntPtr.Zero );
            if ( _changeJournalRootHandle.ToInt32 ( ) == PinvokeWin32.INVALID_HANDLE_VALUE )
            {
                throw new IOException ( "CreateFile() returned invalid handle",
                    new Win32Exception ( Marshal.GetLastWin32Error ( ) ) );
            }
        }                                               // GetRootHandleRead

        private void GetRootHandleWrite ( string drive )
        {  // my modification
            string vol = string.Concat ( "\\\\.\\", drive );
            _changeJournalRootHandle = PinvokeWin32.CreateFile ( vol,
                 PinvokeWin32.GENERIC_READ,
                 PinvokeWin32.FILE_SHARE_WRITE,
                 IntPtr.Zero,
                 PinvokeWin32.OPEN_EXISTING,
                 0,
                 IntPtr.Zero );
            if ( _changeJournalRootHandle.ToInt32 ( ) == PinvokeWin32.INVALID_HANDLE_VALUE )
            {
                throw new IOException ( "CreateFile() returned invalid handle",
                    new Win32Exception ( Marshal.GetLastWin32Error ( ) ) );
            }
        }                                               // GetRootHandleRead

        unsafe private void CreateChangeJournal ( )
        {
            // This function creates a journal on the volume. If a journal already   
            // exists this function will adjust the MaximumSize and AllocationDelta   
            // parameters of the journal   
            UInt64 MaximumSize = 0x800000;   // UInt64 MAX: 18,446,744,073,709,551,615 = 0x1000000000000BD00;
            //       UInt64 MaximumSize = 0x8000000000;   // DEBUG - did not work 12/24/2018
            UInt64 AllocationDelta = 0x100000;   
            PinvokeWin32.CREATE_USN_JOURNAL_DATA cujd;
            cujd.MaximumSize = MaximumSize;
            cujd.AllocationDelta = AllocationDelta;
            // Marshal structure
            int sizeCujd = Marshal.SizeOf ( cujd );
            IntPtr cujdBuffer = Marshal.AllocHGlobal ( sizeCujd );
            PinvokeWin32.ZeroMemory ( cujdBuffer, sizeCujd );
            Marshal.StructureToPtr ( cujd, cujdBuffer, true );

            bool fOk = PinvokeWin32.DeviceIoControl ( _changeJournalRootHandle, PinvokeWin32.FSCTL_CREATE_USN_JOURNAL,
                cujdBuffer, sizeCujd, IntPtr.Zero, 0, out UInt32 cb, IntPtr.Zero );
            if ( !fOk )
            {
                throw new IOException ( "DeviceIoControl() returned false", new Win32Exception ( Marshal.GetLastWin32Error ( ) ) );
            }
        }                                               // CreateChangeJournal      

        unsafe private void EnumerateFiles ( IntPtr medBuffer, ref Dictionary<ulong, FileNameAndFrn> files,
                                                                    string[ ] fileExtensions )
        {
            IntPtr pData = Marshal.AllocHGlobal ( sizeof ( UInt64 ) + 0x10000 );
            PinvokeWin32.ZeroMemory ( pData, sizeof ( UInt64 ) + 0x10000 );

            while ( false != PinvokeWin32.DeviceIoControl ( _changeJournalRootHandle, PinvokeWin32.FSCTL_ENUM_USN_DATA, medBuffer,
                                    sizeof ( PinvokeWin32.MFT_ENUM_DATA ), pData, sizeof ( UInt64 ) + 0x10000, out uint outBytesReturned,
                                    IntPtr.Zero ) )
            {
                IntPtr pUsnRecord = new IntPtr ( pData.ToInt32 ( ) + sizeof ( Int64 ) );
                while ( outBytesReturned > 60 )
                {
                    PinvokeWin32.USN_RECORD usn = new PinvokeWin32.USN_RECORD ( pUsnRecord );
                    if ( 0 != ( usn.FileAttributes & PinvokeWin32.FILE_ATTRIBUTE_DIRECTORY ) )
                    {
                        //   
                        // handle directories   
                        //   
                        if ( !directories.ContainsKey ( usn.FileReferenceNumber ) )
                        {
                            directories.Add ( usn.FileReferenceNumber,
                                new FileNameAndFrn ( usn.FileName, usn.ParentFileReferenceNumber ) );
                        }
                        else
                        {   // this is debug code and should be removed when we are certain that   
                            // duplicate frn's don't exist on a given drive.  To date, this exception has   
                            // never been thrown.  Removing this code improves performance....   
                            throw new Exception ( string.Format ( "Duplicate FRN: {0} for {1}",
                                usn.FileReferenceNumber, usn.FileName ) );
                        }
                    }
                    else
                    {
                        //    
                        // handle files   
                        //   
                        bool add = true;
                        if ( fileExtensions != null && fileExtensions.Length != 0 )
                        {
                            add = false;
                            string s = Path.GetExtension ( usn.FileName );
                            foreach ( string extension in fileExtensions )
                            {
                                if ( 0 == string.Compare ( s, extension, true ) )
                                {
                                    add = true;
                                    break;
                                }
                            }
                        }
                        if ( add )
                        {
                            if ( !files.ContainsKey ( usn.FileReferenceNumber ) )
                            {
                                files.Add ( usn.FileReferenceNumber,
                                    new FileNameAndFrn ( usn.FileName, usn.ParentFileReferenceNumber ) );
                            }
                            else
                            {
                                FileNameAndFrn frn = files[ usn.FileReferenceNumber ];
                                if ( 0 != string.Compare ( usn.FileName, frn.Name, true ) )
                                {
                                    Console.WriteLine (
                                        "Attempt to add duplicate file reference number: {0} for file {1}, file from index {2}",
                                        usn.FileReferenceNumber, usn.FileName, frn.Name );
                                    throw new Exception ( string.Format ( "Duplicate FRN: {0} for {1}",
                                        usn.FileReferenceNumber, usn.FileName ) );
                                }
                            }
                        }
                    }
                    pUsnRecord = new IntPtr ( pUsnRecord.ToInt32 ( ) + usn.RecordLength );
                    outBytesReturned -= usn.RecordLength;
                }
                Marshal.WriteInt64 ( medBuffer, Marshal.ReadInt64 ( pData, 0 ) );
            }
            Marshal.FreeHGlobal ( pData );
        }                                               // EnumerateFiles        

        public class FileNameAndFrn
        {
            #region Properties
            private string _name;
            public string Name
            {
                get { return _name; }
                set { _name = value; }
            }

            private UInt64 _parentFrn;
            public UInt64 ParentFrn
            {
                get { return _parentFrn; }
                set { _parentFrn = value; }
            }
            #endregion

            #region Constructor

            public FileNameAndFrn ( string name, UInt64 parentFrn )
            {
                if ( name != null && name.Length > 0 )
                {
                    _name = name;
                }
                else
                {
                    throw new ArgumentException ( "Invalid argument: null or Length = zero", "name" );
                }
                if ( !( parentFrn < 0 ) )
                {
                    _parentFrn = parentFrn;
                }
                else
                {
                    throw new ArgumentException ( "Invalid argument: less than zero", "parentFrn" );
                }
            }
            #endregion
        }

        public class USN_RECORD
        {
            public UInt32 RecordLength;
            public UInt64 FileReferenceNumber;
            public UInt64 ParentFileReferenceNumber;
            public UInt32 FileAttributes;
            public Int32 FileNameLength;
            public Int32 FileNameOffset;
            public string FileName = string.Empty;

            private const int FR_OFFSET = 8;
            private const int PFR_OFFSET = 16;
            private const int FA_OFFSET = 52;
            private const int FNL_OFFSET = 56;
            private const int FN_OFFSET = 58;

            public USN_RECORD ( IntPtr p )
            {
                this.RecordLength = ( UInt32 )Marshal.ReadInt32 ( p );
                this.FileReferenceNumber = ( UInt64 )Marshal.ReadInt64 ( p, FR_OFFSET );
                this.ParentFileReferenceNumber = ( UInt64 )Marshal.ReadInt64 ( p, PFR_OFFSET );
                this.FileAttributes = ( UInt32 )Marshal.ReadInt32 ( p, FA_OFFSET );
                this.FileNameLength = Marshal.ReadInt16 ( p, FNL_OFFSET );
                this.FileNameOffset = Marshal.ReadInt16 ( p, FN_OFFSET );
                FileName = Marshal.PtrToStringUni ( new IntPtr ( p.ToInt32 ( ) + this.FileNameOffset ), this.FileNameLength / sizeof ( char ) );
            }
        }
        #endregion
    }                                               // class PinvokeWin32

    public class ReadFile_One
    {
        [System.Runtime.InteropServices.StructLayoutAttribute ( System.Runtime.InteropServices.LayoutKind.Sequential )]
        public struct OVERLAPPED
        {
            /// ULONG_PTR->unsigned int
            public uint Internal;
            /// ULONG_PTR->unsigned int
            public uint InternalHigh;
            /// Anonymous_7416d31a_1ce9_4e50_b1e1_0f2ad25c0196
            public Anonymous_7416d31a_1ce9_4e50_b1e1_0f2ad25c0196 Union1;
            /// HANDLE->void*
            public System.IntPtr hEvent;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute ( System.Runtime.InteropServices.LayoutKind.Explicit )]
        public struct Anonymous_7416d31a_1ce9_4e50_b1e1_0f2ad25c0196
        {
            /// Anonymous_ac6e4301_4438_458f_96dd_e86faeeca2a6
            [System.Runtime.InteropServices.FieldOffsetAttribute ( 0 )]
            public Anonymous_ac6e4301_4438_458f_96dd_e86faeeca2a6 Struct1;
            /// PVOID->void*
            [System.Runtime.InteropServices.FieldOffsetAttribute ( 0 )]
            public System.IntPtr Pointer;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute ( System.Runtime.InteropServices.LayoutKind.Sequential )]
        public struct Anonymous_ac6e4301_4438_458f_96dd_e86faeeca2a6
        {
            /// DWORD->unsigned int
            public uint Offset;
            /// DWORD->unsigned int
            public uint OffsetHigh;
        }

        public partial class NativeMethods
        {
            /// Return Type: BOOL->int
            ///hFile: HANDLE->void*
            ///lpBuffer: LPVOID->void*
            ///nNumberOfBytesToRead: DWORD->unsigned int
            ///lpNumberOfBytesRead: LPDWORD->DWORD*
            ///lpOverlapped: LPOVERLAPPED->_OVERLAPPED*
            [System.Runtime.InteropServices.DllImportAttribute ( "kernel32.dll", EntryPoint = "ReadFile" )]
            [return: System.Runtime.InteropServices.MarshalAsAttribute ( System.Runtime.InteropServices.UnmanagedType.Bool )]
            public static extern bool ReadFile ( [System.Runtime.InteropServices.InAttribute ( )] System.IntPtr hFile, System.IntPtr lpBuffer, uint nNumberOfBytesToRead, System.IntPtr lpNumberOfBytesRead, System.IntPtr lpOverlapped );
        }
    }                                               // class ReadFile_One

    public class ReadFile_Two
    {
        /// Return Type: void
        ///dwErrorCode: DWORD->unsigned int
        ///dwNumberOfBytesTransfered: DWORD->unsigned int
        ///lpOverlapped: LPOVERLAPPED->_OVERLAPPED*
        public delegate void LPOVERLAPPED_COMPLETION_ROUTINE ( uint dwErrorCode, uint dwNumberOfBytesTransfered, ref OVERLAPPED lpOverlapped );

        [System.Runtime.InteropServices.StructLayoutAttribute ( System.Runtime.InteropServices.LayoutKind.Sequential )]
        public struct OVERLAPPED
        {
            /// ULONG_PTR->unsigned int
            public uint Internal;
            /// ULONG_PTR->unsigned int
            public uint InternalHigh;
            /// Anonymous_7416d31a_1ce9_4e50_b1e1_0f2ad25c0196
            public Anonymous_7416d31a_1ce9_4e50_b1e1_0f2ad25c0196 Union1;
            /// HANDLE->void*
            public System.IntPtr hEvent;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute ( System.Runtime.InteropServices.LayoutKind.Explicit )]
        public struct Anonymous_7416d31a_1ce9_4e50_b1e1_0f2ad25c0196
        {
            /// Anonymous_ac6e4301_4438_458f_96dd_e86faeeca2a6
            [System.Runtime.InteropServices.FieldOffsetAttribute ( 0 )]
            public Anonymous_ac6e4301_4438_458f_96dd_e86faeeca2a6 Struct1;
            /// PVOID->void*
            [System.Runtime.InteropServices.FieldOffsetAttribute ( 0 )]
            public System.IntPtr Pointer;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute ( System.Runtime.InteropServices.LayoutKind.Sequential )]
        public struct Anonymous_ac6e4301_4438_458f_96dd_e86faeeca2a6
        {
            /// DWORD->unsigned int
            public uint Offset;
            /// DWORD->unsigned int
            public uint OffsetHigh;
        }

        public partial class NativeMethods
        {
            /// Return Type: BOOL->int
            ///hFile: HANDLE->void*
            ///lpBuffer: LPVOID->void*
            ///nNumberOfBytesToRead: DWORD->unsigned int
            ///lpOverlapped: LPOVERLAPPED->_OVERLAPPED*
            ///lpCompletionRoutine: LPOVERLAPPED_COMPLETION_ROUTINE
            [System.Runtime.InteropServices.DllImportAttribute ( "kernel32.dll", EntryPoint = "ReadFileEx" )]
            [return: System.Runtime.InteropServices.MarshalAsAttribute ( System.Runtime.InteropServices.UnmanagedType.Bool )]
            public static extern bool ReadFileEx ( [System.Runtime.InteropServices.InAttribute ( )] System.IntPtr hFile,
                System.IntPtr lpBuffer, uint nNumberOfBytesToRead, ref OVERLAPPED lpOverlapped,
                LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine );
        }

    }                                               // class ReadFile_Two

    public class ReadFile_Three
    {
        [System.Runtime.InteropServices.StructLayoutAttribute (
                                                System.Runtime.InteropServices.LayoutKind.Explicit )]
        public struct FILE_SEGMENT_ELEMENT
        {
            /// PVOID64->void*
            [System.Runtime.InteropServices.FieldOffsetAttribute ( 0 )]
            public System.IntPtr Buffer;
            /// ULONGLONG->unsigned __int64
            [System.Runtime.InteropServices.FieldOffsetAttribute ( 0 )]
            public ulong Alignment;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute ( System.Runtime.InteropServices.LayoutKind.Sequential )]
        public struct OVERLAPPED
        {
            /// ULONG_PTR->unsigned int
            public uint Internal;
            /// ULONG_PTR->unsigned int
            public uint InternalHigh;
            /// Anonymous_7416d31a_1ce9_4e50_b1e1_0f2ad25c0196
            public Anonymous_7416d31a_1ce9_4e50_b1e1_0f2ad25c0196 Union1;
            /// HANDLE->void*
            public System.IntPtr hEvent;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute ( System.Runtime.InteropServices.LayoutKind.Explicit )]
        public struct Anonymous_7416d31a_1ce9_4e50_b1e1_0f2ad25c0196
        {
            /// Anonymous_ac6e4301_4438_458f_96dd_e86faeeca2a6
            [System.Runtime.InteropServices.FieldOffsetAttribute ( 0 )]
            public Anonymous_ac6e4301_4438_458f_96dd_e86faeeca2a6 Struct1;
            /// PVOID->void*
            [System.Runtime.InteropServices.FieldOffsetAttribute ( 0 )]
            public System.IntPtr Pointer;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute ( System.Runtime.InteropServices.LayoutKind.Sequential )]
        public struct Anonymous_ac6e4301_4438_458f_96dd_e86faeeca2a6
        {
            /// DWORD->unsigned int
            public uint Offset;
            /// DWORD->unsigned int
            public uint OffsetHigh;
        }

        public partial class NativeMethods
        {
            /// Return Type: BOOL->int
            ///hFile: HANDLE->void*
            ///aSegmentArray: FILE_SEGMENT_ELEMENT*
            ///nNumberOfBytesToRead: DWORD->unsigned int
            ///lpReserved: LPDWORD->DWORD*
            ///lpOverlapped: LPOVERLAPPED->_OVERLAPPED*
            [System.Runtime.InteropServices.DllImportAttribute ( "kernel32.dll", EntryPoint = "ReadFileScatter" )]
            [return: System.Runtime.InteropServices.MarshalAsAttribute ( System.Runtime.InteropServices.UnmanagedType.Bool )]
            public static extern bool ReadFileScatter ( [System.Runtime.InteropServices.InAttribute ( )] System.IntPtr hFile, [System.Runtime.InteropServices.InAttribute ( )] ref FILE_SEGMENT_ELEMENT aSegmentArray, uint nNumberOfBytesToRead, System.IntPtr lpReserved, ref OVERLAPPED lpOverlapped );
        }

    }                                               // class ReadFile_Three

    public class CreateFile_One
    {
        [System.Runtime.InteropServices.StructLayoutAttribute (
                                            System.Runtime.InteropServices.LayoutKind.Sequential )]
        public struct SECURITY_ATTRIBUTES
        {
            /// DWORD->unsigned int
            public uint nLength;
            /// LPVOID->void*
            public System.IntPtr lpSecurityDescriptor;
            /// BOOL->int
            [System.Runtime.InteropServices.MarshalAsAttribute ( System.Runtime.InteropServices.UnmanagedType.Bool )]
            public bool bInheritHandle;
        }

        public partial class NativeMethods
        {
            /// Return Type: HANDLE->void*
            ///lpFileName: LPCSTR->CHAR*
            ///dwDesiredAccess: DWORD->unsigned int
            ///dwShareMode: DWORD->unsigned int
            ///lpSecurityAttributes: LPSECURITY_ATTRIBUTES->_SECURITY_ATTRIBUTES*
            ///dwCreationDisposition: DWORD->unsigned int
            ///dwFlagsAndAttributes: DWORD->unsigned int
            ///hTemplateFile: HANDLE->void*
            [System.Runtime.InteropServices.DllImportAttribute ( "kernel32.dll", EntryPoint = "CreateFileA" )]
            public static extern System.IntPtr CreateFileA (
                [System.Runtime.InteropServices.InAttribute ( )] 
                [System.Runtime.InteropServices.MarshalAsAttribute (
                    System.Runtime.InteropServices.UnmanagedType.LPStr )] string lpFileName,
                uint dwDesiredAccess, uint dwShareMode,
                [System.Runtime.InteropServices.InAttribute ( )] System.IntPtr lpSecurityAttributes,
                uint dwCreationDisposition, uint dwFlagsAndAttributes,
                [System.Runtime.InteropServices.InAttribute ( )] System.IntPtr hTemplateFile );
        }

    }                                               // class CreateFile_One

    public class CreateFile_Two
    {
        [System.Runtime.InteropServices.StructLayoutAttribute ( System.Runtime.InteropServices.LayoutKind.Sequential )]
        public struct SECURITY_ATTRIBUTES
        {
            /// DWORD->unsigned int
            public uint nLength;
            /// LPVOID->void*
            public System.IntPtr lpSecurityDescriptor;
            /// BOOL->int
            [System.Runtime.InteropServices.MarshalAsAttribute ( System.Runtime.InteropServices.UnmanagedType.Bool )]
            public bool bInheritHandle;
        }

        public partial class NativeMethods
        {
            /// Return Type: HANDLE->void*
            ///lpFileName: LPCWSTR->WCHAR*
            ///dwDesiredAccess: DWORD->unsigned int
            ///dwShareMode: DWORD->unsigned int
            ///lpSecurityAttributes: LPSECURITY_ATTRIBUTES->_SECURITY_ATTRIBUTES*
            ///dwCreationDisposition: DWORD->unsigned int
            ///dwFlagsAndAttributes: DWORD->unsigned int
            ///hTemplateFile: HANDLE->void*
            [System.Runtime.InteropServices.DllImportAttribute ( "kernel32.dll", EntryPoint = "CreateFileW" )]
            public static extern System.IntPtr CreateFileW ( [System.Runtime.InteropServices.InAttribute ( )] [System.Runtime.InteropServices.MarshalAsAttribute ( System.Runtime.InteropServices.UnmanagedType.LPWStr )] string lpFileName, uint dwDesiredAccess, uint dwShareMode, [System.Runtime.InteropServices.InAttribute ( )] System.IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, [System.Runtime.InteropServices.InAttribute ( )] System.IntPtr hTemplateFile );
        }

    }                                               // class CreateFile_Two

    public class CreateFile_Three
    {
        public partial class NativeConstants
        {
            /// CreateFileMapping -> CreateFileMappingW
            /// Error generating expression: Value CreateFileMappingW is not resolved
            public const string CreateFileMapping = "CreateFileMappingW";
        }

    }                                               // class CreateFile_Three

    public class CreateFile_Four
    {
        [System.Runtime.InteropServices.StructLayoutAttribute ( System.Runtime.InteropServices.LayoutKind.Sequential )]
        public struct IMoniker
        {
            /// IMonikerVtbl*
            public System.IntPtr lpVtbl;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute ( System.Runtime.InteropServices.LayoutKind.Sequential )]
        public struct IMonikerVtbl
        {
            /// IMonikerVtbl_QueryInterface
            public IMonikerVtbl_QueryInterface AnonymousMember1;
            /// IMonikerVtbl_AddRef
            public IMonikerVtbl_AddRef AnonymousMember2;
            /// IMonikerVtbl_Release
            public IMonikerVtbl_Release AnonymousMember3;
            /// IMonikerVtbl_GetClassID
            public IMonikerVtbl_GetClassID AnonymousMember4;
            /// IMonikerVtbl_IsDirty
            public IMonikerVtbl_IsDirty AnonymousMember5;
            /// IMonikerVtbl_Load
            public IMonikerVtbl_Load AnonymousMember6;
            /// IMonikerVtbl_Save
            public IMonikerVtbl_Save AnonymousMember7;
            /// IMonikerVtbl_GetSizeMax
            public IMonikerVtbl_GetSizeMax AnonymousMember8;
            /// IMonikerVtbl_BindToObject
            public IMonikerVtbl_BindToObject AnonymousMember9;
            /// IMonikerVtbl_BindToStorage
            public IMonikerVtbl_BindToStorage AnonymousMember10;
            /// IMonikerVtbl_Reduce
            public IMonikerVtbl_Reduce AnonymousMember11;
            /// IMonikerVtbl_ComposeWith
            public IMonikerVtbl_ComposeWith AnonymousMember12;
            /// IMonikerVtbl_Enum
            public IMonikerVtbl_Enum AnonymousMember13;
            /// IMonikerVtbl_IsEqual
            public IMonikerVtbl_IsEqual AnonymousMember14;
            /// IMonikerVtbl_Hash
            public IMonikerVtbl_Hash AnonymousMember15;
            /// IMonikerVtbl_IsRunning
            public IMonikerVtbl_IsRunning AnonymousMember16;
            /// IMonikerVtbl_GetTimeOfLastChange
            public IMonikerVtbl_GetTimeOfLastChange AnonymousMember17;
            /// IMonikerVtbl_Inverse
            public IMonikerVtbl_Inverse AnonymousMember18;
            /// IMonikerVtbl_CommonPrefixWith
            public IMonikerVtbl_CommonPrefixWith AnonymousMember19;
            /// IMonikerVtbl_RelativePathTo
            public IMonikerVtbl_RelativePathTo AnonymousMember20;
            /// IMonikerVtbl_GetDisplayName
            public IMonikerVtbl_GetDisplayName AnonymousMember21;
            /// IMonikerVtbl_ParseDisplayName
            public IMonikerVtbl_ParseDisplayName AnonymousMember22;
            /// IMonikerVtbl_IsSystemMoniker
            public IMonikerVtbl_IsSystemMoniker AnonymousMember23;
        }

        /// Return Type: HRESULT->LONG->int
        ///This: IMoniker*
        ///riid: IID*
        ///ppvObject: void**
        [System.Runtime.InteropServices.UnmanagedFunctionPointerAttribute ( System.Runtime.InteropServices.CallingConvention.StdCall )]
        public delegate int IMonikerVtbl_QueryInterface ( ref IMoniker This, ref GUID riid, ref System.IntPtr ppvObject );

        /// Return Type: ULONG->unsigned int
        ///This: IMoniker*
        [System.Runtime.InteropServices.UnmanagedFunctionPointerAttribute ( System.Runtime.InteropServices.CallingConvention.StdCall )]
        public delegate uint IMonikerVtbl_AddRef ( ref IMoniker This );

        /// Return Type: ULONG->unsigned int
        ///This: IMoniker*
        [System.Runtime.InteropServices.UnmanagedFunctionPointerAttribute ( System.Runtime.InteropServices.CallingConvention.StdCall )]
        public delegate uint IMonikerVtbl_Release ( ref IMoniker This );

        /// Return Type: HRESULT->LONG->int
        ///This: IMoniker*
        ///pClassID: CLSID*
        [System.Runtime.InteropServices.UnmanagedFunctionPointerAttribute ( System.Runtime.InteropServices.CallingConvention.StdCall )]
        public delegate int IMonikerVtbl_GetClassID ( ref IMoniker This, ref GUID pClassID );

        /// Return Type: HRESULT->LONG->int
        ///This: IMoniker*
        [System.Runtime.InteropServices.UnmanagedFunctionPointerAttribute ( System.Runtime.InteropServices.CallingConvention.StdCall )]
        public delegate int IMonikerVtbl_IsDirty ( ref IMoniker This );

        /// Return Type: HRESULT->LONG->int
        ///This: IMoniker*
        ///pStm: IStream*
        [System.Runtime.InteropServices.UnmanagedFunctionPointerAttribute ( System.Runtime.InteropServices.CallingConvention.StdCall )]
        public delegate int IMonikerVtbl_Load ( ref IMoniker This, ref IStream pStm );

        /// Return Type: HRESULT->LONG->int
        ///This: IMoniker*
        ///pStm: IStream*
        ///fClearDirty: BOOL->int
        [System.Runtime.InteropServices.UnmanagedFunctionPointerAttribute ( System.Runtime.InteropServices.CallingConvention.StdCall )]
        public delegate int IMonikerVtbl_Save ( ref IMoniker This, ref IStream pStm, [System.Runtime.InteropServices.MarshalAsAttribute ( System.Runtime.InteropServices.UnmanagedType.Bool )] bool fClearDirty );

        /// Return Type: HRESULT->LONG->int
        ///This: IMoniker*
        ///pcbSize: ULARGE_INTEGER*
        [System.Runtime.InteropServices.UnmanagedFunctionPointerAttribute ( System.Runtime.InteropServices.CallingConvention.StdCall )]
        public delegate int IMonikerVtbl_GetSizeMax ( ref IMoniker This, ref ULARGE_INTEGER pcbSize );

        /// Return Type: HRESULT->LONG->int
        ///This: IMoniker*
        ///pbc: IBindCtx*
        ///pmkToLeft: IMoniker*
        ///riidResult: IID*
        ///ppvResult: void**
        [System.Runtime.InteropServices.UnmanagedFunctionPointerAttribute ( System.Runtime.InteropServices.CallingConvention.StdCall )]
        public delegate int IMonikerVtbl_BindToObject ( ref IMoniker This, ref IBindCtx pbc, ref IMoniker pmkToLeft, ref GUID riidResult, ref System.IntPtr ppvResult );

        /// Return Type: HRESULT->LONG->int
        ///This: IMoniker*
        ///pbc: IBindCtx*
        ///pmkToLeft: IMoniker*
        ///riid: IID*
        ///ppvObj: void**
        [System.Runtime.InteropServices.UnmanagedFunctionPointerAttribute ( System.Runtime.InteropServices.CallingConvention.StdCall )]
        public delegate int IMonikerVtbl_BindToStorage ( ref IMoniker This, ref IBindCtx pbc, ref IMoniker pmkToLeft, ref GUID riid, ref System.IntPtr ppvObj );

        /// Return Type: HRESULT->LONG->int
        ///This: IMoniker*
        ///pbc: IBindCtx*
        ///dwReduceHowFar: DWORD->unsigned int
        ///ppmkToLeft: IMoniker**
        ///ppmkReduced: IMoniker**
        [System.Runtime.InteropServices.UnmanagedFunctionPointerAttribute ( System.Runtime.InteropServices.CallingConvention.StdCall )]
        public delegate int IMonikerVtbl_Reduce ( ref IMoniker This, ref IBindCtx pbc, uint dwReduceHowFar, ref System.IntPtr ppmkToLeft, ref System.IntPtr ppmkReduced );

        /// Return Type: HRESULT->LONG->int
        ///This: IMoniker*
        ///pmkRight: IMoniker*
        ///fOnlyIfNotGeneric: BOOL->int
        ///ppmkComposite: IMoniker**
        [System.Runtime.InteropServices.UnmanagedFunctionPointerAttribute ( System.Runtime.InteropServices.CallingConvention.StdCall )]
        public delegate int IMonikerVtbl_ComposeWith ( ref IMoniker This, ref IMoniker pmkRight, [System.Runtime.InteropServices.MarshalAsAttribute ( System.Runtime.InteropServices.UnmanagedType.Bool )] bool fOnlyIfNotGeneric, ref System.IntPtr ppmkComposite );

        /// Return Type: HRESULT->LONG->int
        ///This: IMoniker*
        ///fForward: BOOL->int
        ///ppenumMoniker: IEnumMoniker**
        [System.Runtime.InteropServices.UnmanagedFunctionPointerAttribute ( System.Runtime.InteropServices.CallingConvention.StdCall )]
        public delegate int IMonikerVtbl_Enum ( ref IMoniker This, [System.Runtime.InteropServices.MarshalAsAttribute ( System.Runtime.InteropServices.UnmanagedType.Bool )] bool fForward, ref System.IntPtr ppenumMoniker );

        /// Return Type: HRESULT->LONG->int
        ///This: IMoniker*
        ///pmkOtherMoniker: IMoniker*
        [System.Runtime.InteropServices.UnmanagedFunctionPointerAttribute ( System.Runtime.InteropServices.CallingConvention.StdCall )]
        public delegate int IMonikerVtbl_IsEqual ( ref IMoniker This, ref IMoniker pmkOtherMoniker );

        /// Return Type: HRESULT->LONG->int
        ///This: IMoniker*
        ///pdwHash: DWORD*
        [System.Runtime.InteropServices.UnmanagedFunctionPointerAttribute ( System.Runtime.InteropServices.CallingConvention.StdCall )]
        public delegate int IMonikerVtbl_Hash ( ref IMoniker This, ref uint pdwHash );

        /// Return Type: HRESULT->LONG->int
        ///This: IMoniker*
        ///pbc: IBindCtx*
        ///pmkToLeft: IMoniker*
        ///pmkNewlyRunning: IMoniker*
        [System.Runtime.InteropServices.UnmanagedFunctionPointerAttribute ( System.Runtime.InteropServices.CallingConvention.StdCall )]
        public delegate int IMonikerVtbl_IsRunning ( ref IMoniker This, ref IBindCtx pbc, ref IMoniker pmkToLeft, ref IMoniker pmkNewlyRunning );

        /// Return Type: HRESULT->LONG->int
        ///This: IMoniker*
        ///pbc: IBindCtx*
        ///pmkToLeft: IMoniker*
        ///pFileTime: FILETIME*
        [System.Runtime.InteropServices.UnmanagedFunctionPointerAttribute ( System.Runtime.InteropServices.CallingConvention.StdCall )]
        public delegate int IMonikerVtbl_GetTimeOfLastChange ( ref IMoniker This, ref IBindCtx pbc, ref IMoniker pmkToLeft, ref FILETIME pFileTime );

        /// Return Type: HRESULT->LONG->int
        ///This: IMoniker*
        ///ppmk: IMoniker**
        [System.Runtime.InteropServices.UnmanagedFunctionPointerAttribute ( System.Runtime.InteropServices.CallingConvention.StdCall )]
        public delegate int IMonikerVtbl_Inverse ( ref IMoniker This, ref System.IntPtr ppmk );

        /// Return Type: HRESULT->LONG->int
        ///This: IMoniker*
        ///pmkOther: IMoniker*
        ///ppmkPrefix: IMoniker**
        [System.Runtime.InteropServices.UnmanagedFunctionPointerAttribute ( System.Runtime.InteropServices.CallingConvention.StdCall )]
        public delegate int IMonikerVtbl_CommonPrefixWith ( ref IMoniker This, ref IMoniker pmkOther, ref System.IntPtr ppmkPrefix );

        /// Return Type: HRESULT->LONG->int
        ///This: IMoniker*
        ///pmkOther: IMoniker*
        ///ppmkRelPath: IMoniker**
        [System.Runtime.InteropServices.UnmanagedFunctionPointerAttribute ( System.Runtime.InteropServices.CallingConvention.StdCall )]
        public delegate int IMonikerVtbl_RelativePathTo ( ref IMoniker This, ref IMoniker pmkOther, ref System.IntPtr ppmkRelPath );

        /// Return Type: HRESULT->LONG->int
        ///This: IMoniker*
        ///pbc: IBindCtx*
        ///pmkToLeft: IMoniker*
        ///ppszDisplayName: LPOLESTR*
        [System.Runtime.InteropServices.UnmanagedFunctionPointerAttribute ( System.Runtime.InteropServices.CallingConvention.StdCall )]
        public delegate int IMonikerVtbl_GetDisplayName ( ref IMoniker This, ref IBindCtx pbc, ref IMoniker pmkToLeft, ref System.IntPtr ppszDisplayName );

        /// Return Type: HRESULT->LONG->int
        ///This: IMoniker*
        ///pbc: IBindCtx*
        ///pmkToLeft: IMoniker*
        ///pszDisplayName: LPOLESTR->OLECHAR*
        ///pchEaten: ULONG*
        ///ppmkOut: IMoniker**
        [System.Runtime.InteropServices.UnmanagedFunctionPointerAttribute ( System.Runtime.InteropServices.CallingConvention.StdCall )]
        public delegate int IMonikerVtbl_ParseDisplayName ( ref IMoniker This, ref IBindCtx pbc, ref IMoniker pmkToLeft, System.IntPtr pszDisplayName, ref uint pchEaten, ref System.IntPtr ppmkOut );

        /// Return Type: HRESULT->LONG->int
        ///This: IMoniker*
        ///pdwMksys: DWORD*
        [System.Runtime.InteropServices.UnmanagedFunctionPointerAttribute ( System.Runtime.InteropServices.CallingConvention.StdCall )]
        public delegate int IMonikerVtbl_IsSystemMoniker ( ref IMoniker This, ref uint pdwMksys );

        [System.Runtime.InteropServices.StructLayoutAttribute ( System.Runtime.InteropServices.LayoutKind.Sequential )]
        public struct IStream
        {
            /// IStreamVtbl*
            public System.IntPtr lpVtbl;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute ( System.Runtime.InteropServices.LayoutKind.Sequential )]
        public struct IBindCtx
        {
            /// IBindCtxVtbl*
            public System.IntPtr lpVtbl;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute ( System.Runtime.InteropServices.LayoutKind.Sequential )]
        public struct IEnumMoniker
        {
            /// IEnumMonikerVtbl*
            public System.IntPtr lpVtbl;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute ( System.Runtime.InteropServices.LayoutKind.Explicit )]
        public struct ULARGE_INTEGER
        {
            /// Anonymous_652f900e_e9d5_4a81_ba95_5c3af2ba5157
            [System.Runtime.InteropServices.FieldOffsetAttribute ( 0 )]
            public Anonymous_652f900e_e9d5_4a81_ba95_5c3af2ba5157 Struct1;
            /// Anonymous_da3d5bb2_d7f6_4b49_a86f_df044e26e59a
            [System.Runtime.InteropServices.FieldOffsetAttribute ( 0 )]
            public Anonymous_da3d5bb2_d7f6_4b49_a86f_df044e26e59a u;
            /// ULONGLONG->unsigned __int64
            [System.Runtime.InteropServices.FieldOffsetAttribute ( 0 )]
            public ulong QuadPart;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute ( System.Runtime.InteropServices.LayoutKind.Sequential )]
        public struct FILETIME
        {
            /// DWORD->unsigned int
            public uint dwLowDateTime;
            /// DWORD->unsigned int
            public uint dwHighDateTime;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute ( System.Runtime.InteropServices.LayoutKind.Sequential )]
        public struct IStreamVtbl
        {
            /// IStreamVtbl_QueryInterface
            public IStreamVtbl_QueryInterface AnonymousMember1;
            /// IStreamVtbl_AddRef
            public IStreamVtbl_AddRef AnonymousMember2;
            /// IStreamVtbl_Release
            public IStreamVtbl_Release AnonymousMember3;
            /// IStreamVtbl_Read
            public IStreamVtbl_Read AnonymousMember4;
            /// IStreamVtbl_Write
            public IStreamVtbl_Write AnonymousMember5;
            /// IStreamVtbl_Seek
            public IStreamVtbl_Seek AnonymousMember6;
            /// IStreamVtbl_SetSize
            public IStreamVtbl_SetSize AnonymousMember7;
            /// IStreamVtbl_CopyTo
            public IStreamVtbl_CopyTo AnonymousMember8;
            /// IStreamVtbl_Commit
            public IStreamVtbl_Commit AnonymousMember9;
            /// IStreamVtbl_Revert
            public IStreamVtbl_Revert AnonymousMember10;
            /// IStreamVtbl_LockRegion
            public IStreamVtbl_LockRegion AnonymousMember11;
            /// IStreamVtbl_UnlockRegion
            public IStreamVtbl_UnlockRegion AnonymousMember12;
            /// IStreamVtbl_Stat
            public IStreamVtbl_Stat AnonymousMember13;
            /// IStreamVtbl_Clone
            public IStreamVtbl_Clone AnonymousMember14;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute ( System.Runtime.InteropServices.LayoutKind.Sequential )]
        public struct IBindCtxVtbl
        {
            /// IBindCtxVtbl_QueryInterface
            public IBindCtxVtbl_QueryInterface AnonymousMember1;
            /// IBindCtxVtbl_AddRef
            public IBindCtxVtbl_AddRef AnonymousMember2;
            /// IBindCtxVtbl_Release
            public IBindCtxVtbl_Release AnonymousMember3;
            /// IBindCtxVtbl_RegisterObjectBound
            public IBindCtxVtbl_RegisterObjectBound AnonymousMember4;
            /// IBindCtxVtbl_RevokeObjectBound
            public IBindCtxVtbl_RevokeObjectBound AnonymousMember5;
            /// IBindCtxVtbl_ReleaseBoundObjects
            public IBindCtxVtbl_ReleaseBoundObjects AnonymousMember6;
            /// IBindCtxVtbl_SetBindOptions
            public IBindCtxVtbl_SetBindOptions AnonymousMember7;
            /// IBindCtxVtbl_GetBindOptions
            public IBindCtxVtbl_GetBindOptions AnonymousMember8;
            /// IBindCtxVtbl_GetRunningObjectTable
            public IBindCtxVtbl_GetRunningObjectTable AnonymousMember9;
            /// IBindCtxVtbl_RegisterObjectParam
            public IBindCtxVtbl_RegisterObjectParam AnonymousMember10;
            /// IBindCtxVtbl_GetObjectParam
            public IBindCtxVtbl_GetObjectParam AnonymousMember11;
            /// IBindCtxVtbl_EnumObjectParam
            public IBindCtxVtbl_EnumObjectParam AnonymousMember12;
            /// IBindCtxVtbl_RevokeObjectParam
            public IBindCtxVtbl_RevokeObjectParam AnonymousMember13;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute ( System.Runtime.InteropServices.LayoutKind.Sequential )]
        public struct IEnumMonikerVtbl
        {
            /// IEnumMonikerVtbl_QueryInterface
            public IEnumMonikerVtbl_QueryInterface AnonymousMember1;
            /// IEnumMonikerVtbl_AddRef
            public IEnumMonikerVtbl_AddRef AnonymousMember2;
            /// IEnumMonikerVtbl_Release
            public IEnumMonikerVtbl_Release AnonymousMember3;
            /// IEnumMonikerVtbl_Next
            public IEnumMonikerVtbl_Next AnonymousMember4;
            /// IEnumMonikerVtbl_Skip
            public IEnumMonikerVtbl_Skip AnonymousMember5;
            /// IEnumMonikerVtbl_Reset
            public IEnumMonikerVtbl_Reset AnonymousMember6;
            /// IEnumMonikerVtbl_Clone
            public IEnumMonikerVtbl_Clone AnonymousMember7;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute ( System.Runtime.InteropServices.LayoutKind.Sequential, CharSet = System.Runtime.InteropServices.CharSet.Ansi )]
        public struct GUID
        {
            /// unsigned int
            public uint Data1;
            /// unsigned short
            public ushort Data2;
            /// unsigned short
            public ushort Data3;
            /// unsigned char[8]
            [System.Runtime.InteropServices.MarshalAsAttribute ( System.Runtime.InteropServices.UnmanagedType.ByValTStr, SizeConst = 8 )]
            public string Data4;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute ( System.Runtime.InteropServices.LayoutKind.Sequential )]
        public struct Anonymous_652f900e_e9d5_4a81_ba95_5c3af2ba5157
        {
            /// DWORD->unsigned int
            public uint LowPart;
            /// DWORD->unsigned int
            public uint HighPart;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute ( System.Runtime.InteropServices.LayoutKind.Sequential )]
        public struct Anonymous_da3d5bb2_d7f6_4b49_a86f_df044e26e59a
        {
            /// DWORD->unsigned int
            public uint LowPart;
            /// DWORD->unsigned int
            public uint HighPart;
        }

        /// Return Type: HRESULT->LONG->int
        ///This: IStream*
        ///riid: IID*
        ///ppvObject: void**
        [System.Runtime.InteropServices.UnmanagedFunctionPointerAttribute ( System.Runtime.InteropServices.CallingConvention.StdCall )]
        public delegate int IStreamVtbl_QueryInterface ( ref IStream This, ref GUID riid, ref System.IntPtr ppvObject );

        /// Return Type: ULONG->unsigned int
        ///This: IStream*
        [System.Runtime.InteropServices.UnmanagedFunctionPointerAttribute ( System.Runtime.InteropServices.CallingConvention.StdCall )]
        public delegate uint IStreamVtbl_AddRef ( ref IStream This );

        /// Return Type: ULONG->unsigned int
        ///This: IStream*
        [System.Runtime.InteropServices.UnmanagedFunctionPointerAttribute ( System.Runtime.InteropServices.CallingConvention.StdCall )]
        public delegate uint IStreamVtbl_Release ( ref IStream This );

        /// Return Type: HRESULT->LONG->int
        ///This: IStream*
        ///pv: void*
        ///cb: ULONG->unsigned int
        ///pcbRead: ULONG*
        [System.Runtime.InteropServices.UnmanagedFunctionPointerAttribute ( System.Runtime.InteropServices.CallingConvention.StdCall )]
        public delegate int IStreamVtbl_Read ( ref IStream This, System.IntPtr pv, uint cb, ref uint pcbRead );

        /// Return Type: HRESULT->LONG->int
        ///This: IStream*
        ///pv: void*
        ///cb: ULONG->unsigned int
        ///pcbWritten: ULONG*
        [System.Runtime.InteropServices.UnmanagedFunctionPointerAttribute ( System.Runtime.InteropServices.CallingConvention.StdCall )]
        public delegate int IStreamVtbl_Write ( ref IStream This, System.IntPtr pv, uint cb, ref uint pcbWritten );

        /// Return Type: HRESULT->LONG->int
        ///This: IStream*
        ///dlibMove: LARGE_INTEGER->_LARGE_INTEGER
        ///dwOrigin: DWORD->unsigned int
        ///plibNewPosition: ULARGE_INTEGER*
        [System.Runtime.InteropServices.UnmanagedFunctionPointerAttribute ( System.Runtime.InteropServices.CallingConvention.StdCall )]
        public delegate int IStreamVtbl_Seek ( ref IStream This, LARGE_INTEGER dlibMove, uint dwOrigin, ref ULARGE_INTEGER plibNewPosition );

        /// Return Type: HRESULT->LONG->int
        ///This: IStream*
        ///libNewSize: ULARGE_INTEGER->_ULARGE_INTEGER
        [System.Runtime.InteropServices.UnmanagedFunctionPointerAttribute ( System.Runtime.InteropServices.CallingConvention.StdCall )]
        public delegate int IStreamVtbl_SetSize ( ref IStream This, ULARGE_INTEGER libNewSize );

        /// Return Type: HRESULT->LONG->int
        ///This: IStream*
        ///pstm: IStream*
        ///cb: ULARGE_INTEGER->_ULARGE_INTEGER
        ///pcbRead: ULARGE_INTEGER*
        ///pcbWritten: ULARGE_INTEGER*
        [System.Runtime.InteropServices.UnmanagedFunctionPointerAttribute ( System.Runtime.InteropServices.CallingConvention.StdCall )]
        public delegate int IStreamVtbl_CopyTo ( ref IStream This, ref IStream pstm, ULARGE_INTEGER cb, ref ULARGE_INTEGER pcbRead, ref ULARGE_INTEGER pcbWritten );

        /// Return Type: HRESULT->LONG->int
        ///This: IStream*
        ///grfCommitFlags: DWORD->unsigned int
        [System.Runtime.InteropServices.UnmanagedFunctionPointerAttribute ( System.Runtime.InteropServices.CallingConvention.StdCall )]
        public delegate int IStreamVtbl_Commit ( ref IStream This, uint grfCommitFlags );

        /// Return Type: HRESULT->LONG->int
        ///This: IStream*
        [System.Runtime.InteropServices.UnmanagedFunctionPointerAttribute ( System.Runtime.InteropServices.CallingConvention.StdCall )]
        public delegate int IStreamVtbl_Revert ( ref IStream This );

        /// Return Type: HRESULT->LONG->int
        ///This: IStream*
        ///libOffset: ULARGE_INTEGER->_ULARGE_INTEGER
        ///cb: ULARGE_INTEGER->_ULARGE_INTEGER
        ///dwLockType: DWORD->unsigned int
        [System.Runtime.InteropServices.UnmanagedFunctionPointerAttribute ( System.Runtime.InteropServices.CallingConvention.StdCall )]
        public delegate int IStreamVtbl_LockRegion ( ref IStream This, ULARGE_INTEGER libOffset, ULARGE_INTEGER cb, uint dwLockType );

        /// Return Type: HRESULT->LONG->int
        ///This: IStream*
        ///libOffset: ULARGE_INTEGER->_ULARGE_INTEGER
        ///cb: ULARGE_INTEGER->_ULARGE_INTEGER
        ///dwLockType: DWORD->unsigned int
        [System.Runtime.InteropServices.UnmanagedFunctionPointerAttribute ( System.Runtime.InteropServices.CallingConvention.StdCall )]
        public delegate int IStreamVtbl_UnlockRegion ( ref IStream This, ULARGE_INTEGER libOffset, ULARGE_INTEGER cb, uint dwLockType );

        /// Return Type: HRESULT->LONG->int
        ///This: IStream*
        ///pstatstg: STATSTG*
        ///grfStatFlag: DWORD->unsigned int
        [System.Runtime.InteropServices.UnmanagedFunctionPointerAttribute ( System.Runtime.InteropServices.CallingConvention.StdCall )]
        public delegate int IStreamVtbl_Stat ( ref IStream This, ref tagSTATSTG pstatstg, uint grfStatFlag );

        /// Return Type: HRESULT->LONG->int
        ///This: IStream*
        ///ppstm: IStream**
        [System.Runtime.InteropServices.UnmanagedFunctionPointerAttribute ( System.Runtime.InteropServices.CallingConvention.StdCall )]
        public delegate int IStreamVtbl_Clone ( ref IStream This, ref System.IntPtr ppstm );

        /// Return Type: HRESULT->LONG->int
        ///This: IBindCtx*
        ///riid: IID*
        ///ppvObject: void**
        [System.Runtime.InteropServices.UnmanagedFunctionPointerAttribute ( System.Runtime.InteropServices.CallingConvention.StdCall )]
        public delegate int IBindCtxVtbl_QueryInterface ( ref IBindCtx This, ref GUID riid, ref System.IntPtr ppvObject );

        /// Return Type: ULONG->unsigned int
        ///This: IBindCtx*
        [System.Runtime.InteropServices.UnmanagedFunctionPointerAttribute ( System.Runtime.InteropServices.CallingConvention.StdCall )]
        public delegate uint IBindCtxVtbl_AddRef ( ref IBindCtx This );

        /// Return Type: ULONG->unsigned int
        ///This: IBindCtx*
        [System.Runtime.InteropServices.UnmanagedFunctionPointerAttribute ( System.Runtime.InteropServices.CallingConvention.StdCall )]
        public delegate uint IBindCtxVtbl_Release ( ref IBindCtx This );

        /// Return Type: HRESULT->LONG->int
        ///This: IBindCtx*
        ///punk: IUnknown*
        [System.Runtime.InteropServices.UnmanagedFunctionPointerAttribute ( System.Runtime.InteropServices.CallingConvention.StdCall )]
        public delegate int IBindCtxVtbl_RegisterObjectBound ( ref IBindCtx This, ref IUnknown punk );

        /// Return Type: HRESULT->LONG->int
        ///This: IBindCtx*
        ///punk: IUnknown*
        [System.Runtime.InteropServices.UnmanagedFunctionPointerAttribute ( System.Runtime.InteropServices.CallingConvention.StdCall )]
        public delegate int IBindCtxVtbl_RevokeObjectBound ( ref IBindCtx This, ref IUnknown punk );

        /// Return Type: HRESULT->LONG->int
        ///This: IBindCtx*
        [System.Runtime.InteropServices.UnmanagedFunctionPointerAttribute ( System.Runtime.InteropServices.CallingConvention.StdCall )]
        public delegate int IBindCtxVtbl_ReleaseBoundObjects ( ref IBindCtx This );

        /// Return Type: HRESULT->LONG->int
        ///This: IBindCtx*
        ///pbindopts: BIND_OPTS*
        [System.Runtime.InteropServices.UnmanagedFunctionPointerAttribute ( System.Runtime.InteropServices.CallingConvention.StdCall )]
        public delegate int IBindCtxVtbl_SetBindOptions ( ref IBindCtx This, ref tagBIND_OPTS pbindopts );

        /// Return Type: HRESULT->LONG->int
        ///This: IBindCtx*
        ///pbindopts: BIND_OPTS*
        [System.Runtime.InteropServices.UnmanagedFunctionPointerAttribute ( System.Runtime.InteropServices.CallingConvention.StdCall )]
        public delegate int IBindCtxVtbl_GetBindOptions ( ref IBindCtx This, ref tagBIND_OPTS pbindopts );

        /// Return Type: HRESULT->LONG->int
        ///This: IBindCtx*
        ///pprot: IRunningObjectTable**
        [System.Runtime.InteropServices.UnmanagedFunctionPointerAttribute ( System.Runtime.InteropServices.CallingConvention.StdCall )]
        public delegate int IBindCtxVtbl_GetRunningObjectTable ( ref IBindCtx This, ref System.IntPtr pprot );

        /// Return Type: HRESULT->LONG->int
        ///This: IBindCtx*
        ///pszKey: LPOLESTR->OLECHAR*
        ///punk: IUnknown*
        [System.Runtime.InteropServices.UnmanagedFunctionPointerAttribute ( System.Runtime.InteropServices.CallingConvention.StdCall )]
        public delegate int IBindCtxVtbl_RegisterObjectParam ( ref IBindCtx This, System.IntPtr pszKey, ref IUnknown punk );

        /// Return Type: HRESULT->LONG->int
        ///This: IBindCtx*
        ///pszKey: LPOLESTR->OLECHAR*
        ///ppunk: IUnknown**
        [System.Runtime.InteropServices.UnmanagedFunctionPointerAttribute ( System.Runtime.InteropServices.CallingConvention.StdCall )]
        public delegate int IBindCtxVtbl_GetObjectParam ( ref IBindCtx This, System.IntPtr pszKey, ref System.IntPtr ppunk );

        /// Return Type: HRESULT->LONG->int
        ///This: IBindCtx*
        ///ppenum: IEnumString**
        [System.Runtime.InteropServices.UnmanagedFunctionPointerAttribute ( System.Runtime.InteropServices.CallingConvention.StdCall )]
        public delegate int IBindCtxVtbl_EnumObjectParam ( ref IBindCtx This, ref System.IntPtr ppenum );

        /// Return Type: HRESULT->LONG->int
        ///This: IBindCtx*
        ///pszKey: LPOLESTR->OLECHAR*
        [System.Runtime.InteropServices.UnmanagedFunctionPointerAttribute ( System.Runtime.InteropServices.CallingConvention.StdCall )]
        public delegate int IBindCtxVtbl_RevokeObjectParam ( ref IBindCtx This, System.IntPtr pszKey );

        /// Return Type: HRESULT->LONG->int
        ///This: IEnumMoniker*
        ///riid: IID*
        ///ppvObject: void**
        [System.Runtime.InteropServices.UnmanagedFunctionPointerAttribute ( System.Runtime.InteropServices.CallingConvention.StdCall )]
        public delegate int IEnumMonikerVtbl_QueryInterface ( ref IEnumMoniker This, ref GUID riid, ref System.IntPtr ppvObject );

        /// Return Type: ULONG->unsigned int
        ///This: IEnumMoniker*
        [System.Runtime.InteropServices.UnmanagedFunctionPointerAttribute ( System.Runtime.InteropServices.CallingConvention.StdCall )]
        public delegate uint IEnumMonikerVtbl_AddRef ( ref IEnumMoniker This );

        /// Return Type: ULONG->unsigned int
        ///This: IEnumMoniker*
        [System.Runtime.InteropServices.UnmanagedFunctionPointerAttribute ( System.Runtime.InteropServices.CallingConvention.StdCall )]
        public delegate uint IEnumMonikerVtbl_Release ( ref IEnumMoniker This );

        /// Return Type: HRESULT->LONG->int
        ///This: IEnumMoniker*
        ///celt: ULONG->unsigned int
        ///rgelt: IMoniker**
        ///pceltFetched: ULONG*
        [System.Runtime.InteropServices.UnmanagedFunctionPointerAttribute ( System.Runtime.InteropServices.CallingConvention.StdCall )]
        public delegate int IEnumMonikerVtbl_Next ( ref IEnumMoniker This, uint celt, ref System.IntPtr rgelt, ref uint pceltFetched );

        /// Return Type: HRESULT->LONG->int
        ///This: IEnumMoniker*
        ///celt: ULONG->unsigned int
        [System.Runtime.InteropServices.UnmanagedFunctionPointerAttribute ( System.Runtime.InteropServices.CallingConvention.StdCall )]
        public delegate int IEnumMonikerVtbl_Skip ( ref IEnumMoniker This, uint celt );

        /// Return Type: HRESULT->LONG->int
        ///This: IEnumMoniker*
        [System.Runtime.InteropServices.UnmanagedFunctionPointerAttribute ( System.Runtime.InteropServices.CallingConvention.StdCall )]
        public delegate int IEnumMonikerVtbl_Reset ( ref IEnumMoniker This );

        /// Return Type: HRESULT->LONG->int
        ///This: IEnumMoniker*
        ///ppenum: IEnumMoniker**
        [System.Runtime.InteropServices.UnmanagedFunctionPointerAttribute ( System.Runtime.InteropServices.CallingConvention.StdCall )]
        public delegate int IEnumMonikerVtbl_Clone ( ref IEnumMoniker This, ref System.IntPtr ppenum );

        [System.Runtime.InteropServices.StructLayoutAttribute ( System.Runtime.InteropServices.LayoutKind.Sequential )]
        public struct IUnknown
        {
            /// IUnknownVtbl*
            public System.IntPtr lpVtbl;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute ( System.Runtime.InteropServices.LayoutKind.Sequential )]
        public struct IRunningObjectTable
        {
            /// IRunningObjectTableVtbl*
            public System.IntPtr lpVtbl;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute ( System.Runtime.InteropServices.LayoutKind.Sequential )]
        public struct IEnumString
        {
            /// IEnumStringVtbl*
            public System.IntPtr lpVtbl;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute ( System.Runtime.InteropServices.LayoutKind.Explicit )]
        public struct LARGE_INTEGER
        {
            /// Anonymous_9320654f_2227_43bf_a385_74cc8c562686
            [System.Runtime.InteropServices.FieldOffsetAttribute ( 0 )]
            public Anonymous_9320654f_2227_43bf_a385_74cc8c562686 Struct1;

            /// Anonymous_947eb392_1446_4e25_bbd4_10e98165f3a9
            [System.Runtime.InteropServices.FieldOffsetAttribute ( 0 )]
            public Anonymous_947eb392_1446_4e25_bbd4_10e98165f3a9 u;

            /// LONGLONG->__int64
            [System.Runtime.InteropServices.FieldOffsetAttribute ( 0 )]
            public long QuadPart;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute ( System.Runtime.InteropServices.LayoutKind.Sequential )]
        public struct tagSTATSTG
        {
            /// LPOLESTR->OLECHAR*
            [System.Runtime.InteropServices.MarshalAsAttribute ( System.Runtime.InteropServices.UnmanagedType.LPWStr )]
            public string pwcsName;
            /// DWORD->unsigned int
            public uint type;
            /// ULARGE_INTEGER->_ULARGE_INTEGER
            public ULARGE_INTEGER cbSize;
            /// FILETIME->_FILETIME
            public FILETIME mtime;
            /// FILETIME->_FILETIME
            public FILETIME ctime;
            /// FILETIME->_FILETIME
            public FILETIME atime;
            /// DWORD->unsigned int
            public uint grfMode;
            /// DWORD->unsigned int
            public uint grfLocksSupported;
            /// CLSID->GUID->_GUID
            public GUID clsid;
            /// DWORD->unsigned int
            public uint grfStateBits;
            /// DWORD->unsigned int
            public uint reserved;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute ( System.Runtime.InteropServices.LayoutKind.Sequential )]
        public struct tagBIND_OPTS
        {
            /// DWORD->unsigned int
            public uint cbStruct;
            /// DWORD->unsigned int
            public uint grfFlags;
            /// DWORD->unsigned int
            public uint grfMode;
            /// DWORD->unsigned int
            public uint dwTickCountDeadline;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute ( System.Runtime.InteropServices.LayoutKind.Sequential )]
        public struct IUnknownVtbl
        {
            /// IUnknownVtbl_QueryInterface
            public IUnknownVtbl_QueryInterface AnonymousMember1;
            /// IUnknownVtbl_AddRef
            public IUnknownVtbl_AddRef AnonymousMember2;
            /// IUnknownVtbl_Release
            public IUnknownVtbl_Release AnonymousMember3;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute ( System.Runtime.InteropServices.LayoutKind.Sequential )]
        public struct IRunningObjectTableVtbl
        {
            /// IRunningObjectTableVtbl_QueryInterface
            public IRunningObjectTableVtbl_QueryInterface AnonymousMember1;
            /// IRunningObjectTableVtbl_AddRef
            public IRunningObjectTableVtbl_AddRef AnonymousMember2;
            /// IRunningObjectTableVtbl_Release
            public IRunningObjectTableVtbl_Release AnonymousMember3;
            /// IRunningObjectTableVtbl_Register
            public IRunningObjectTableVtbl_Register AnonymousMember4;
            /// IRunningObjectTableVtbl_Revoke
            public IRunningObjectTableVtbl_Revoke AnonymousMember5;
            /// IRunningObjectTableVtbl_IsRunning
            public IRunningObjectTableVtbl_IsRunning AnonymousMember6;
            /// IRunningObjectTableVtbl_GetObjectW
            public IRunningObjectTableVtbl_GetObjectW AnonymousMember7;
            /// IRunningObjectTableVtbl_NoteChangeTime
            public IRunningObjectTableVtbl_NoteChangeTime AnonymousMember8;
            /// IRunningObjectTableVtbl_GetTimeOfLastChange
            public IRunningObjectTableVtbl_GetTimeOfLastChange AnonymousMember9;
            /// IRunningObjectTableVtbl_EnumRunning
            public IRunningObjectTableVtbl_EnumRunning AnonymousMember10;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute ( System.Runtime.InteropServices.LayoutKind.Sequential )]
        public struct IEnumStringVtbl
        {
            /// IEnumStringVtbl_QueryInterface
            public IEnumStringVtbl_QueryInterface AnonymousMember1;
            /// IEnumStringVtbl_AddRef
            public IEnumStringVtbl_AddRef AnonymousMember2;
            /// IEnumStringVtbl_Release
            public IEnumStringVtbl_Release AnonymousMember3;
            /// IEnumStringVtbl_Next
            public IEnumStringVtbl_Next AnonymousMember4;
            /// IEnumStringVtbl_Skip
            public IEnumStringVtbl_Skip AnonymousMember5;
            /// IEnumStringVtbl_Reset
            public IEnumStringVtbl_Reset AnonymousMember6;
            /// IEnumStringVtbl_Clone
            public IEnumStringVtbl_Clone AnonymousMember7;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute ( System.Runtime.InteropServices.LayoutKind.Sequential )]
        public struct Anonymous_9320654f_2227_43bf_a385_74cc8c562686
        {
            /// DWORD->unsigned int
            public uint LowPart;
            /// LONG->int
            public int HighPart;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute ( System.Runtime.InteropServices.LayoutKind.Sequential )]
        public struct Anonymous_947eb392_1446_4e25_bbd4_10e98165f3a9
        {
            /// DWORD->unsigned int
            public uint LowPart;
            /// LONG->int
            public int HighPart;
        }

        /// Return Type: HRESULT->LONG->int
        ///This: IUnknown*
        ///riid: IID*
        ///ppvObject: void**
        [System.Runtime.InteropServices.UnmanagedFunctionPointerAttribute ( System.Runtime.InteropServices.CallingConvention.StdCall )]
        public delegate int IUnknownVtbl_QueryInterface ( ref IUnknown This, ref GUID riid, ref System.IntPtr ppvObject );

        /// Return Type: ULONG->unsigned int
        ///This: IUnknown*
        [System.Runtime.InteropServices.UnmanagedFunctionPointerAttribute ( System.Runtime.InteropServices.CallingConvention.StdCall )]
        public delegate uint IUnknownVtbl_AddRef ( ref IUnknown This );

        /// Return Type: ULONG->unsigned int
        ///This: IUnknown*
        [System.Runtime.InteropServices.UnmanagedFunctionPointerAttribute ( System.Runtime.InteropServices.CallingConvention.StdCall )]
        public delegate uint IUnknownVtbl_Release ( ref IUnknown This );

        /// Return Type: HRESULT->LONG->int
        ///This: IRunningObjectTable*
        ///riid: IID*
        ///ppvObject: void**
        [System.Runtime.InteropServices.UnmanagedFunctionPointerAttribute ( System.Runtime.InteropServices.CallingConvention.StdCall )]
        public delegate int IRunningObjectTableVtbl_QueryInterface ( ref IRunningObjectTable This, ref GUID riid, ref System.IntPtr ppvObject );

        /// Return Type: ULONG->unsigned int
        ///This: IRunningObjectTable*
        [System.Runtime.InteropServices.UnmanagedFunctionPointerAttribute ( System.Runtime.InteropServices.CallingConvention.StdCall )]
        public delegate uint IRunningObjectTableVtbl_AddRef ( ref IRunningObjectTable This );

        /// Return Type: ULONG->unsigned int
        ///This: IRunningObjectTable*
        [System.Runtime.InteropServices.UnmanagedFunctionPointerAttribute ( System.Runtime.InteropServices.CallingConvention.StdCall )]
        public delegate uint IRunningObjectTableVtbl_Release ( ref IRunningObjectTable This );

        /// Return Type: HRESULT->LONG->int
        ///This: IRunningObjectTable*
        ///grfFlags: DWORD->unsigned int
        ///punkObject: IUnknown*
        ///pmkObjectName: IMoniker*
        ///pdwRegister: DWORD*
        [System.Runtime.InteropServices.UnmanagedFunctionPointerAttribute ( System.Runtime.InteropServices.CallingConvention.StdCall )]
        public delegate int IRunningObjectTableVtbl_Register ( ref IRunningObjectTable This, uint grfFlags, ref IUnknown punkObject, ref IMoniker pmkObjectName, ref uint pdwRegister );

        /// Return Type: HRESULT->LONG->int
        ///This: IRunningObjectTable*
        ///dwRegister: DWORD->unsigned int
        [System.Runtime.InteropServices.UnmanagedFunctionPointerAttribute ( System.Runtime.InteropServices.CallingConvention.StdCall )]
        public delegate int IRunningObjectTableVtbl_Revoke ( ref IRunningObjectTable This, uint dwRegister );

        /// Return Type: HRESULT->LONG->int
        ///This: IRunningObjectTable*
        ///pmkObjectName: IMoniker*
        [System.Runtime.InteropServices.UnmanagedFunctionPointerAttribute ( System.Runtime.InteropServices.CallingConvention.StdCall )]
        public delegate int IRunningObjectTableVtbl_IsRunning ( ref IRunningObjectTable This, ref IMoniker pmkObjectName );

        /// Return Type: HRESULT->LONG->int
        ///This: IRunningObjectTable*
        ///pmkObjectName: IMoniker*
        ///ppunkObject: IUnknown**
        [System.Runtime.InteropServices.UnmanagedFunctionPointerAttribute ( System.Runtime.InteropServices.CallingConvention.StdCall )]
        public delegate int IRunningObjectTableVtbl_GetObjectW ( ref IRunningObjectTable This, ref IMoniker pmkObjectName, ref System.IntPtr ppunkObject );

        /// Return Type: HRESULT->LONG->int
        ///This: IRunningObjectTable*
        ///dwRegister: DWORD->unsigned int
        ///pfiletime: FILETIME*
        [System.Runtime.InteropServices.UnmanagedFunctionPointerAttribute ( System.Runtime.InteropServices.CallingConvention.StdCall )]
        public delegate int IRunningObjectTableVtbl_NoteChangeTime ( ref IRunningObjectTable This, uint dwRegister, ref FILETIME pfiletime );

        /// Return Type: HRESULT->LONG->int
        ///This: IRunningObjectTable*
        ///pmkObjectName: IMoniker*
        ///pfiletime: FILETIME*
        [System.Runtime.InteropServices.UnmanagedFunctionPointerAttribute ( System.Runtime.InteropServices.CallingConvention.StdCall )]
        public delegate int IRunningObjectTableVtbl_GetTimeOfLastChange ( ref IRunningObjectTable This, ref IMoniker pmkObjectName, ref FILETIME pfiletime );

        /// Return Type: HRESULT->LONG->int
        ///This: IRunningObjectTable*
        ///ppenumMoniker: IEnumMoniker**
        [System.Runtime.InteropServices.UnmanagedFunctionPointerAttribute ( System.Runtime.InteropServices.CallingConvention.StdCall )]
        public delegate int IRunningObjectTableVtbl_EnumRunning ( ref IRunningObjectTable This, ref System.IntPtr ppenumMoniker );

        /// Return Type: HRESULT->LONG->int
        ///This: IEnumString*
        ///riid: IID*
        ///ppvObject: void**
        [System.Runtime.InteropServices.UnmanagedFunctionPointerAttribute ( System.Runtime.InteropServices.CallingConvention.StdCall )]
        public delegate int IEnumStringVtbl_QueryInterface ( ref IEnumString This, ref GUID riid, ref System.IntPtr ppvObject );

        /// Return Type: ULONG->unsigned int
        ///This: IEnumString*
        [System.Runtime.InteropServices.UnmanagedFunctionPointerAttribute ( System.Runtime.InteropServices.CallingConvention.StdCall )]
        public delegate uint IEnumStringVtbl_AddRef ( ref IEnumString This );

        /// Return Type: ULONG->unsigned int
        ///This: IEnumString*
        [System.Runtime.InteropServices.UnmanagedFunctionPointerAttribute ( System.Runtime.InteropServices.CallingConvention.StdCall )]
        public delegate uint IEnumStringVtbl_Release ( ref IEnumString This );

        /// Return Type: HRESULT->LONG->int
        ///This: IEnumString*
        ///celt: ULONG->unsigned int
        ///rgelt: LPOLESTR*
        ///pceltFetched: ULONG*
        [System.Runtime.InteropServices.UnmanagedFunctionPointerAttribute ( System.Runtime.InteropServices.CallingConvention.StdCall )]
        public delegate int IEnumStringVtbl_Next ( ref IEnumString This, uint celt, ref System.IntPtr rgelt, ref uint pceltFetched );

        /// Return Type: HRESULT->LONG->int
        ///This: IEnumString*
        ///celt: ULONG->unsigned int
        [System.Runtime.InteropServices.UnmanagedFunctionPointerAttribute ( System.Runtime.InteropServices.CallingConvention.StdCall )]
        public delegate int IEnumStringVtbl_Skip ( ref IEnumString This, uint celt );

        /// Return Type: HRESULT->LONG->int
        ///This: IEnumString*
        [System.Runtime.InteropServices.UnmanagedFunctionPointerAttribute ( System.Runtime.InteropServices.CallingConvention.StdCall )]
        public delegate int IEnumStringVtbl_Reset ( ref IEnumString This );

        /// Return Type: HRESULT->LONG->int
        ///This: IEnumString*
        ///ppenum: IEnumString**
        [System.Runtime.InteropServices.UnmanagedFunctionPointerAttribute ( System.Runtime.InteropServices.CallingConvention.StdCall )]
        public delegate int IEnumStringVtbl_Clone ( ref IEnumString This, ref System.IntPtr ppenum );

        public partial class NativeMethods
        {
            /// Return Type: HRESULT->LONG->int
            ///lpszPathName: LPCOLESTR->OLECHAR*
            ///ppmk: LPMONIKER*
            [System.Runtime.InteropServices.DllImportAttribute ( "ole32.dll", EntryPoint = "CreateFileMoniker", CallingConvention = System.Runtime.InteropServices.CallingConvention.StdCall )]
            public static extern int CreateFileMoniker ( [System.Runtime.InteropServices.InAttribute ( )] [System.Runtime.InteropServices.MarshalAsAttribute ( System.Runtime.InteropServices.UnmanagedType.LPWStr )] string lpszPathName, ref System.IntPtr ppmk );
        }
    }                                               // class CreateFile_Four

    public class CreateFile_Five
    {
        [System.Runtime.InteropServices.StructLayoutAttribute ( System.Runtime.InteropServices.LayoutKind.Sequential )]
        public struct SECURITY_ATTRIBUTES
        {
            /// DWORD->unsigned int
            public uint nLength;
            /// LPVOID->void*
            public System.IntPtr lpSecurityDescriptor;
            /// BOOL->int
            [System.Runtime.InteropServices.MarshalAsAttribute ( System.Runtime.InteropServices.UnmanagedType.Bool )]
            public bool bInheritHandle;
        }

        public partial class NativeMethods
        {
            /// Return Type: HANDLE->void*
            ///hFile: HANDLE->void*
            ///lpFileMappingAttributes: LPSECURITY_ATTRIBUTES->_SECURITY_ATTRIBUTES*
            ///flProtect: DWORD->unsigned int
            ///dwMaximumSizeHigh: DWORD->unsigned int
            ///dwMaximumSizeLow: DWORD->unsigned int
            ///lpName: LPCSTR->CHAR*
            [System.Runtime.InteropServices.DllImportAttribute ( "kernel32.dll", EntryPoint = "CreateFileMappingA" )]
            public static extern System.IntPtr CreateFileMappingA ( [System.Runtime.InteropServices.InAttribute ( )] System.IntPtr hFile, [System.Runtime.InteropServices.InAttribute ( )] System.IntPtr lpFileMappingAttributes, uint flProtect, uint dwMaximumSizeHigh, uint dwMaximumSizeLow, [System.Runtime.InteropServices.InAttribute ( )] [System.Runtime.InteropServices.MarshalAsAttribute ( System.Runtime.InteropServices.UnmanagedType.LPStr )] string lpName );
        }

    }                                               // class CreateFile_Five

    public class CreateFile_Six
    {

        [System.Runtime.InteropServices.StructLayoutAttribute ( System.Runtime.InteropServices.LayoutKind.Sequential )]
        public struct SECURITY_ATTRIBUTES
        {
            /// DWORD->unsigned int
            public uint nLength;
            /// LPVOID->void*
            public System.IntPtr lpSecurityDescriptor;
            /// BOOL->int
            [System.Runtime.InteropServices.MarshalAsAttribute (
                System.Runtime.InteropServices.UnmanagedType.Bool )]
            public bool bInheritHandle;
        }

        public partial class NativeMethods
        {
            /// Return Type: HANDLE->void*
            ///hFile: HANDLE->void*
            ///lpFileMappingAttributes: LPSECURITY_ATTRIBUTES->_SECURITY_ATTRIBUTES*
            ///flProtect: DWORD->unsigned int
            ///dwMaximumSizeHigh: DWORD->unsigned int
            ///dwMaximumSizeLow: DWORD->unsigned int
            ///lpName: LPCWSTR->WCHAR*
            [System.Runtime.InteropServices.DllImportAttribute ( "kernel32.dll", EntryPoint = "CreateFileMappingW" )]
            public static extern System.IntPtr CreateFileMappingW (
                [System.Runtime.InteropServices.InAttribute ( )] System.IntPtr hFile,
                [System.Runtime.InteropServices.InAttribute ( )] System.IntPtr lpFileMappingAttributes,
                uint flProtect, uint dwMaximumSizeHigh, uint dwMaximumSizeLow,
                [System.Runtime.InteropServices.InAttribute ( )] [System.Runtime.InteropServices.MarshalAsAttribute ( System.Runtime.InteropServices.UnmanagedType.LPWStr )] string lpName );
        }

    }                                               // class CreateFile_Six

    public class DiskClone
    {
        private bool completionCode = false;
        public const UInt32 GENERIC_READ = 0x80000000;
        public const UInt32 GENERIC_WRITE = 0x40000000;
        public const UInt32 FILE_SHARE_READ = 0x00000001;
        public const UInt32 FILE_SHARE_WRITE = 0x00000002;
        public const UInt32 FILE_ATTRIBUTE_DEVICE = 0x00000040;
        public const UInt32 OPEN_EXISTING = 3;
        public const UInt32 CREATE_ALWAYS = 0x00000002;
        public const UInt32 FILE_FLAG_NO_BUFFERING = 0x20000000;
        public const UInt32 FILE_FLAG_OVERLAPPED = 0x40000000;
        public const long WAIT_IO_COMPLETION = 0x000000C0L;
        public const UInt32 FILE_BEGIN = 0x00000000;
        public const UInt32 FILE_CURRENT = 0x00000001;

        public const UInt32 IOCTL_DISK_GET_LENGTH_INFO = 0;
        public const UInt32 IOCTL_DISK_GET_DRIVE_GEOMETRY_EX = 1;
        public const Int32 INVALID_HANDLE_VALUE = -1;


        [System.Runtime.InteropServices.StructLayoutAttribute ( System.Runtime.InteropServices.LayoutKind.Sequential )]
        public struct OVERLAPPED
        {
            /// ULONG_PTR->unsigned int
            public uint Internal;
            /// ULONG_PTR->unsigned int
            public uint InternalHigh;
            /// Anonymous_7416d31a_1ce9_4e50_b1e1_0f2ad25c0196
            public Anonymous_7416d31a_1ce9_4e50_b1e1_0f2ad25c0196 Union1;
            /// HANDLE->void*
            public System.IntPtr hEvent;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute ( System.Runtime.InteropServices.LayoutKind.Sequential )]
        public struct GET_LENGTH_INFORMATION
        {
            public LARGE_INTEGER Length;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute ( System.Runtime.InteropServices.LayoutKind.Explicit )]
        public struct Anonymous_7416d31a_1ce9_4e50_b1e1_0f2ad25c0196
        {
            /// Anonymous_ac6e4301_4438_458f_96dd_e86faeeca2a6
            [System.Runtime.InteropServices.FieldOffsetAttribute ( 0 )]
            public Anonymous_ac6e4301_4438_458f_96dd_e86faeeca2a6 Struct1;
            /// PVOID->void*
            [System.Runtime.InteropServices.FieldOffsetAttribute ( 0 )]
            public System.IntPtr Pointer;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute ( System.Runtime.InteropServices.LayoutKind.Sequential )]
        public struct Anonymous_ac6e4301_4438_458f_96dd_e86faeeca2a6
        {
            /// DWORD->unsigned int
            public uint Offset;
            /// DWORD->unsigned int
            public uint OffsetHigh;
        }

        public partial class NativeMethods
        {
            /// Return Type: BOOL->int
            ///hDevice: HANDLE->void*
            ///dwIoControlCode: DWORD->unsigned int
            ///lpInBuffer: LPVOID->void*
            ///nInBufferSize: DWORD->unsigned int
            ///lpOutBuffer: LPVOID->void*
            ///nOutBufferSize: DWORD->unsigned int
            ///lpBytesReturned: LPDWORD->DWORD*
            ///lpOverlapped: LPOVERLAPPED->_OVERLAPPED*
            [System.Runtime.InteropServices.DllImportAttribute ( "kernel32.dll", EntryPoint = "DeviceIoControl" )]
            [return: System.Runtime.InteropServices.MarshalAsAttribute ( System.Runtime.InteropServices.UnmanagedType.Bool )]
            public static extern bool DeviceIoControl ( [System.Runtime.InteropServices.InAttribute ( )] System.IntPtr hDevice, uint dwIoControlCode, [System.Runtime.InteropServices.InAttribute ( )] System.IntPtr lpInBuffer, uint nInBufferSize, System.IntPtr lpOutBuffer, uint nOutBufferSize, System.IntPtr lpBytesReturned, System.IntPtr lpOverlapped );
        }

        [DllImport ( "kernel32.dll", SetLastError = true )]
        public static extern IntPtr CreateFile ( string lpFileName, uint dwDesiredAccess,
                                                  uint dwShareMode, IntPtr lpSecurityAttributes,
                                                  uint dwCreationDisposition, uint dwFlagsAndAttributes,
                                                  IntPtr hTemplateFile );

        [DllImport ( "kernel32.dll", SetLastError = true )]
        [return: MarshalAs ( UnmanagedType.Bool )]
        public static extern bool CloseHandle ( IntPtr hObject );

        [DllImport ( "kernel32.dll" )]
        static extern bool ReadFileScatter ( IntPtr hFile, FILE_SEGMENT_ELEMENT[ ]
           aSegementArray, uint nNumberOfBytesToRead, IntPtr lpReserved,
           [In] ref System.Threading.NativeOverlapped lpOverlapped );

        [DllImport ( "kernel32.dll", SetLastError = true )]
        static extern unsafe int ReadFileScatter ( IntPtr hFile, FILE_SEGMENT_ELEMENT* aSegmentArray,
                        int nNumberOfBytesToRead, IntPtr lpReserved, NativeOverlapped* lpOverlapped );

        [DllImport ( "kernel32.dll", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Auto )]
        [return: MarshalAs ( UnmanagedType.Bool )]
        public static extern bool DeviceIoControl ( IntPtr hDevice,
                                                      UInt32 dwIoControlCode,
                                                      IntPtr lpInBuffer, Int32 nInBufferSize,
                                                      IntPtr lpOutBuffer, Int32 nOutBufferSize,
                                                      out uint lpBytesReturned, IntPtr lpOverlapped );

        [System.Runtime.InteropServices.StructLayoutAttribute ( System.Runtime.InteropServices.LayoutKind.Explicit )]

        public struct FILE_SEGMENT_ELEMENT
        {
            /// PVOID64->void*
            [System.Runtime.InteropServices.FieldOffsetAttribute ( 0 )]
            public System.IntPtr Buffer;
            /// ULONGLONG->unsigned __int64
            [System.Runtime.InteropServices.FieldOffsetAttribute ( 0 )]
            public ulong Alignment;
        }

        public partial class NativeMethods
        {
            /// Return Type: BOOL->int
            ///hFile: HANDLE->void*
            ///aSegmentArray: FILE_SEGMENT_ELEMENT*
            ///nNumberOfBytesToWrite: DWORD->unsigned int
            ///lpReserved: LPDWORD->DWORD*
            ///lpOverlapped: LPOVERLAPPED->_OVERLAPPED*
            [System.Runtime.InteropServices.DllImportAttribute ( "kernel32.dll", EntryPoint = "WriteFileGather" )]
            [return: System.Runtime.InteropServices.MarshalAsAttribute ( System.Runtime.InteropServices.UnmanagedType.Bool )]
            public static extern bool WriteFileGather (
                [System.Runtime.InteropServices.InAttribute ( )] System.IntPtr hFile,
                [System.Runtime.InteropServices.InAttribute ( )] ref FILE_SEGMENT_ELEMENT aSegmentArray,
                uint nNumberOfBytesToWrite, System.IntPtr lpReserved, ref OVERLAPPED lpOverlapped );
        }
        // WriteFileOverlapped ends

        // GetSystemInfo:

        [System.Runtime.InteropServices.StructLayoutAttribute ( System.Runtime.InteropServices.LayoutKind.Sequential )]
        public struct SYSTEM_INFO
        {
            /// Anonymous_459bdf75_2992_4fef_9fb5_389952f59d12
            public Anonymous_459bdf75_2992_4fef_9fb5_389952f59d12 Union1;
            /// DWORD->unsigned int
            public uint dwPageSize;
            /// LPVOID->void*
            public System.IntPtr lpMinimumApplicationAddress;
            /// LPVOID->void*
            public System.IntPtr lpMaximumApplicationAddress;
            /// DWORD_PTR->ULONG_PTR->unsigned int
            public uint dwActiveProcessorMask;
            /// DWORD->unsigned int
            public uint dwNumberOfProcessors;
            /// DWORD->unsigned int
            public uint dwProcessorType;
            /// DWORD->unsigned int
            public uint dwAllocationGranularity;
            /// WORD->unsigned short
            public ushort wProcessorLevel;
            /// WORD->unsigned short
            public ushort wProcessorRevision;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute ( System.Runtime.InteropServices.LayoutKind.Explicit )]
        public struct Anonymous_459bdf75_2992_4fef_9fb5_389952f59d12
        {
            /// DWORD->unsigned int
            [System.Runtime.InteropServices.FieldOffsetAttribute ( 0 )]
            public uint dwOemId;
            /// Anonymous_a30d5f78_3b46_471a_9d25_915a0fe3987d
            [System.Runtime.InteropServices.FieldOffsetAttribute ( 0 )]
            public Anonymous_a30d5f78_3b46_471a_9d25_915a0fe3987d Struct1;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute ( System.Runtime.InteropServices.LayoutKind.Sequential )]
        public struct Anonymous_a30d5f78_3b46_471a_9d25_915a0fe3987d
        {
            /// WORD->unsigned short
            public ushort wProcessorArchitecture;
            /// WORD->unsigned short
            public ushort wReserved;
        }

        public partial class NativeMethods
        {
            /// Return Type: void
            ///lpSystemInfo: LPSYSTEM_INFO->_SYSTEM_INFO*
            [System.Runtime.InteropServices.DllImportAttribute ( "kernel32.dll", EntryPoint = "GetSystemInfo" )]
            public static extern void GetSystemInfo ( [System.Runtime.InteropServices.OutAttribute ( )] out SYSTEM_INFO lpSystemInfo );
        }
        [DllImport ( "kernel32.dll" )]
        static extern bool ReadFile ( IntPtr hFile, byte[ ] lpBuffer,
           uint nNumberOfBytesToRead, out uint lpNumberOfBytesRead, IntPtr lpOverlapped );


        [DllImport ( "kernel32.dll", SetLastError = true )]
        static extern bool ReadFile ( IntPtr hFile, [Out] byte[ ] lpBuffer, uint nNumberOfBytesToRead,
             out uint lpNumberOfBytesRead, [In] ref System.Threading.NativeOverlapped lpOverlapped );
        // or
        [DllImport ( "kernel32.dll", SetLastError = true )]
        private unsafe static extern bool ReadFile (
            int hFile,                        // handle to file
            byte[ ] lpBuffer,                // data buffer
            int nNumberOfBytesToRead,        // number of bytes to read
            ref int lpNumberOfBytesRead,    // number of bytes read
            int* ptr
            // 
            // ref OVERLAPPED lpOverlapped        // overlapped buffer
            );

        /// Return Type: void
        ///dwErrorCode: DWORD->unsigned int
        ///dwNumberOfBytesTransfered: DWORD->unsigned int
        ///lpOverlapped: LPOVERLAPPED->_OVERLAPPED*
        public delegate void LPOVERLAPPED_COMPLETION_ROUTINE ( uint dwErrorCode,
            uint dwNumberOfBytesTransfered, ref OVERLAPPED lpOverlapped );

        public partial class NativeMethods
        {
            /// Return Type: BOOL->int
            ///hFile: HANDLE->void*
            ///lpBuffer: LPVOID->void*
            ///nNumberOfBytesToRead: DWORD->unsigned int
            ///lpOverlapped: LPOVERLAPPED->_OVERLAPPED*
            ///lpCompletionRoutine: LPOVERLAPPED_COMPLETION_ROUTINE
            [System.Runtime.InteropServices.DllImportAttribute ( "kernel32.dll", EntryPoint = "ReadFileEx" )]
            [return: System.Runtime.InteropServices.MarshalAsAttribute ( System.Runtime.InteropServices.UnmanagedType.Bool )]
            public static extern bool ReadFileEx ( [System.Runtime.InteropServices.InAttribute ( )] System.IntPtr hFile,
                System.IntPtr lpBuffer, uint nNumberOfBytesToRead, ref OVERLAPPED lpOverlapped,
                LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine );
        }

        public partial class NativeMethods
        {
            /// Return Type: LPVOID->void*
            ///hProcess: HANDLE->void*
            ///lpAddress: LPVOID->void*
            ///dwSize: SIZE_T->ULONG_PTR->unsigned int
            ///flAllocationType: DWORD->unsigned int
            ///flProtect: DWORD->unsigned int
            [System.Runtime.InteropServices.DllImportAttribute ( "kernel32.dll", EntryPoint = "VirtualAllocEx" )]
            public static extern System.IntPtr VirtualAllocEx ( [System.Runtime.InteropServices.InAttribute ( )] System.IntPtr hProcess, [System.Runtime.InteropServices.InAttribute ( )] System.IntPtr lpAddress,
                uint dwSize, uint flAllocationType, uint flProtect );
        }

        [System.Runtime.InteropServices.StructLayoutAttribute ( System.Runtime.InteropServices.LayoutKind.Explicit )]
        public struct LARGE_INTEGER
        {
            /// Anonymous_9320654f_2227_43bf_a385_74cc8c562686
            [System.Runtime.InteropServices.FieldOffsetAttribute ( 0 )]
            public Anonymous_9320654f_2227_43bf_a385_74cc8c562686 Struct1;
            /// Anonymous_947eb392_1446_4e25_bbd4_10e98165f3a9
            [System.Runtime.InteropServices.FieldOffsetAttribute ( 0 )]
            public Anonymous_947eb392_1446_4e25_bbd4_10e98165f3a9 u;
            /// LONGLONG->__int64
            [System.Runtime.InteropServices.FieldOffsetAttribute ( 0 )]
            public long QuadPart;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute ( System.Runtime.InteropServices.LayoutKind.Sequential )]
        public struct Anonymous_9320654f_2227_43bf_a385_74cc8c562686
        {
            /// DWORD->unsigned int
            public uint LowPart;
            /// LONG->int
            public int HighPart;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute ( System.Runtime.InteropServices.LayoutKind.Sequential )]
        public struct Anonymous_947eb392_1446_4e25_bbd4_10e98165f3a9
        {
            /// DWORD->unsigned int
            public uint LowPart;
            /// LONG->int
            public int HighPart;
        }

        public partial class NativeMethods
        {
            /// Return Type: BOOL->int
            ///hFile: HANDLE->void*
            ///liDistanceToMove: LARGE_INTEGER->_LARGE_INTEGER
            ///lpNewFilePointer: PLARGE_INTEGER->LARGE_INTEGER*
            ///dwMoveMethod: DWORD->unsigned int
            [System.Runtime.InteropServices.DllImportAttribute ( "kernel32.dll", EntryPoint = "SetFilePointerEx" )]
            [return: System.Runtime.InteropServices.MarshalAsAttribute ( System.Runtime.InteropServices.UnmanagedType.Bool )]
            public static extern bool SetFilePointerEx ( [System.Runtime.InteropServices.InAttribute ( )] 
                 System.IntPtr hFile, LARGE_INTEGER liDistanceToMove,
                System.IntPtr lpNewFilePointer, uint dwMoveMethod );
        }

        public partial class NativeMethods
        {
            /// Return Type: BOOL->int
            ///hFile: HANDLE->void*
            ///lpBuffer: LPCVOID->void*
            ///nNumberOfBytesToWrite: DWORD->unsigned int
            ///lpOverlapped: LPOVERLAPPED->_OVERLAPPED*
            ///lpCompletionRoutine: LPOVERLAPPED_COMPLETION_ROUTINE
            [System.Runtime.InteropServices.DllImportAttribute ( "kernel32.dll", EntryPoint = "WriteFileEx" )]
            [return: System.Runtime.InteropServices.MarshalAsAttribute ( System.Runtime.InteropServices.UnmanagedType.Bool )]
            public static extern bool WriteFileEx ( [System.Runtime.InteropServices.InAttribute ( )] 
                 System.IntPtr hFile, [System.Runtime.InteropServices.InAttribute ( )] System.IntPtr lpBuffer,
                 uint nNumberOfBytesToWrite, ref OVERLAPPED lpOverlapped,
                 LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine );
        }

        public void diskRead ( string driveLetterToClone, string driveLetterCloneTo )
        {
            // drive letter is "C:\\" or "C:" or "C"
            //            DriveInfo[ ] allDrives = DriveInfo.GetDrives ( );
            long volumeToCloneSize = GetDiskSize.GetSize ( );
  //          uint lpNumberOfBytesRead = 0;
            Monitors mon = new Monitors ( );
            bool success = false;            
            Auxiliaries axil = new Auxiliaries ( );
            // Has been largely debugged
            unsafe
            {
                string lpFileName = @"\\.\PhysicalDrive0";
                string lpFileName2 = @"\\.\PhysicalDrive1";
                SetControls.setAccessRule ( lpFileName );
                SYSTEM_INFO lpSystemInfo = new SYSTEM_INFO ( );
                NativeMethods.GetSystemInfo ( out lpSystemInfo );
                long numberOfIterations = Math.DivRem ( volumeToCloneSize, lpSystemInfo.dwAllocationGranularity, out long rem );
                Console.WriteLine ( "numberOfIterations = " + numberOfIterations.ToString ( ) +
                    "  rem = " + rem.ToString ( ) + "   VolumeToCloneSize = " + volumeToCloneSize.ToString ( ) );
                long lastIterations = rem / lpSystemInfo.dwPageSize;
                Console.WriteLine ( "PageSize = " + lpSystemInfo.dwPageSize.ToString ( ) );
                Console.WriteLine ( "lpSystemInfo.dwAllocationGranularity:  = " + lpSystemInfo.dwAllocationGranularity.ToString ( ) );
                uint dwDesiredAccess = GENERIC_READ;
                uint dwShareMode = FILE_SHARE_READ;
                IntPtr lpSecurityAttributes = IntPtr.Zero;
                uint dwCreationDisposition = OPEN_EXISTING;
                uint dwFlagsAndAttributes = FILE_ATTRIBUTE_DEVICE | FILE_FLAG_NO_BUFFERING;
                // open Source Drive for read
                IntPtr hFile = CreateFile ( lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes,
                                                      dwCreationDisposition, dwFlagsAndAttributes, IntPtr.Zero );
                dealLastError ( "Create file" );
                // open dest drive for write
                dwDesiredAccess = FILE_SHARE_WRITE;
                dwShareMode = FILE_SHARE_WRITE; 
                IntPtr hFile2 = CreateFile ( lpFileName2, dwDesiredAccess, dwShareMode, lpSecurityAttributes,
                                                      dwCreationDisposition, dwFlagsAndAttributes, IntPtr.Zero );

                OVERLAPPED lpOverlapped = new OVERLAPPED ( );
                LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine =
                                                       new LPOVERLAPPED_COMPLETION_ROUTINE ( target );
                // Moving bytes
                byte[ ] lpBuffer = new byte[ lpSystemInfo.dwAllocationGranularity ];
                GCHandle GCH = GCHandle.Alloc ( lpBuffer, GCHandleType.Pinned );
                IntPtr btp = GCH.AddrOfPinnedObject ( );

                LARGE_INTEGER liDistanceToMove = new LARGE_INTEGER ( );
                liDistanceToMove.QuadPart = lpSystemInfo.dwAllocationGranularity; // 64 K   
                IntPtr point = new IntPtr ( );
                GCH = GCHandle.Alloc ( point, GCHandleType.Pinned );
                System.IntPtr lpNewFilePointer = GCH.AddrOfPinnedObject ( );
                uint dwErrorCode = 0;
                uint dwNumberOfBytesTransfered = 0;
                uint lpNumberOfBytesToRead = lpSystemInfo.dwAllocationGranularity; // 64 K

                // first pointer move, just to place it at the beginning (BOF) for both Disks
                liDistanceToMove.QuadPart = 0x00000000;
                uint dwMoveMethod = FILE_BEGIN;
                success = NativeMethods.SetFilePointerEx ( hFile, liDistanceToMove, IntPtr.Zero, dwMoveMethod );
                dealLastError ( "SetFilePointerEx" );
                success = NativeMethods.SetFilePointerEx ( hFile2, liDistanceToMove, IntPtr.Zero, dwMoveMethod );
                dealLastError ( "SetFilePointerEx" );
                dwMoveMethod = FILE_CURRENT;
                liDistanceToMove.QuadPart = lpSystemInfo.dwAllocationGranularity; // 64 K
                for ( int jj = 0; jj < numberOfIterations; jj++ )
                {
                    this.completionCode = false;
                    mon.AddElement ( lpBuffer );
                    success = false;
                    success = NativeMethods.ReadFileEx ( hFile, btp, lpNumberOfBytesToRead, ref lpOverlapped, lpCompletionRoutine );
                    Thread.Sleep ( 0 );
                    while ( !this.completionCode )
                    {
                        lpCompletionRoutine.Invoke ( dwErrorCode, dwNumberOfBytesTransfered, ref lpOverlapped );
                        if ( this.completionCode )
                        {
                            success = NativeMethods.SetFilePointerEx ( hFile, liDistanceToMove, IntPtr.Zero, dwMoveMethod );
                            //                           mon.DeleteElement ( lpBuffer );
                            NativeMethods.WriteFileEx ( hFile2, btp, lpSystemInfo.dwAllocationGranularity,
                                                          ref  lpOverlapped, lpCompletionRoutine );
                            Thread.Sleep ( 0 );
                            while ( !this.completionCode )
                            {
                                lpCompletionRoutine.Invoke ( dwErrorCode, dwNumberOfBytesTransfered, ref lpOverlapped );
                                if ( this.completionCode )
                                {
                                    success = NativeMethods.SetFilePointerEx ( hFile2, liDistanceToMove, IntPtr.Zero, dwMoveMethod ); mon.DeleteElement ( lpBuffer );
                                    mon.DeleteElement ( lpBuffer );
                                }
                                lpBuffer.Initialize ( );
                                break;
                            }                           
                        }
                    }
                }
                if ( lastIterations != 0 )
                {
                    lpBuffer = new byte[ lpSystemInfo.dwPageSize ];  // buffer is small (4096)
                    GCH = GCHandle.Alloc ( lpBuffer, GCHandleType.Pinned );
                    btp = GCH.AddrOfPinnedObject ( );
                    lpNumberOfBytesToRead = lpSystemInfo.dwPageSize;
                    liDistanceToMove.QuadPart = lpSystemInfo.dwPageSize;
                    for ( int jj = 0; jj < lastIterations; jj++ )
                    {
                        mon.AddElement ( lpBuffer );
                        success = false;
                        this.completionCode = false;
                        success = NativeMethods.ReadFileEx ( hFile, btp, lpNumberOfBytesToRead,
                                                        ref lpOverlapped, lpCompletionRoutine );
                        Thread.Sleep ( 0 );
                        while ( !this.completionCode )
                        {
                            lpCompletionRoutine.Invoke ( dwErrorCode, dwNumberOfBytesTransfered, ref lpOverlapped );
                            if ( this.completionCode )
                            {
                                success = NativeMethods.SetFilePointerEx ( hFile2, liDistanceToMove, IntPtr.Zero, dwMoveMethod ); mon.DeleteElement ( lpBuffer );
                                mon.DeleteElement ( lpBuffer );
                            }
                            lpBuffer.Initialize ( );
                            break;
                        }        
                    }
                }
            }
            
        }                                               // diskRead

        private void target ( uint dwErrorCode, uint dwNumberOfBytesTransfered,
                                 ref OVERLAPPED lpOverlapped )
        {
            if ( dwNumberOfBytesTransfered > 0 )
            {
                this.completionCode = true;
            }
            Console.WriteLine ( "dwNumberOfBytesTransfered: Target " + dwNumberOfBytesTransfered.ToString ( ) );
        }                                               // target     

        private void dealLastError ( string annotate )
        {
            if ( annotate != string.Empty )
            {
                TSP.textToSpeech ( annotate );
            }
            uint error = NativeMethods.GetLastError ( );
            if ( error == 5 )
            {
                TSP.textToSpeech ( annotate + "   Access Denied" );
            }
            else
            {
                if ( error == 0 )
                {
                    TSP.textToSpeech ( "Valid Handle" );
                    Console.WriteLine ( annotate + "  Error = " + error.ToString ( ) );
                }
                else
                {
                    TSP.textToSpeech ( "Another error" );
                    Console.WriteLine ( annotate + "  Error = " + error.ToString ( ) );
                }
            }
        }                                               // dealLastError

        public void diskClone ( )
        {
 //           ULARGE_INTEGER ularge = new ULARGE_INTEGER ( );
            unsafe
            {
                //              ULARGE_INTEGER* lpFreeBytesAvailableToCaller = &ularge;
                string lpDirectoryName = @"\\.\PhysicalDrive0";
                IntPtr lpTotalNumberOfBytes = IntPtr.Zero;
                IntPtr lpTotalNumberOfFreeBytes = IntPtr.Zero;
                IntPtr lpFreeBytesAvailableToCaller = IntPtr.Zero;
                NativeMethods.GetDiskFreeSpaceExA ( lpDirectoryName, lpFreeBytesAvailableToCaller, lpTotalNumberOfBytes, lpTotalNumberOfFreeBytes );
                System.Threading.NativeOverlapped lpOverlapped = new System.Threading.NativeOverlapped ( );
                SYSTEM_INFO lpSystemInfo = new SYSTEM_INFO ( );
                // parameters for NativeOverlapped:
                lpOverlapped.OffsetLow = 0;  // initial.
                lpOverlapped.OffsetHigh = 0; // initial.           
                lpOverlapped.EventHandle = IntPtr.Zero;

                System.Threading.NativeOverlapped* pToOverlp = &lpOverlapped;
                NativeMethods.GetSystemInfo ( out lpSystemInfo );

                string lpFileName = @"\\.\PhysicalDrive0";
                uint dwDesiredAccess = GENERIC_READ;
                uint dwShareMode = FILE_SHARE_READ;
                IntPtr lpSecurityAttributes = IntPtr.Zero;
                uint dwCreationDisposition = OPEN_EXISTING;
                //           uint dwFlagsAndAttributes = FILE_ATTRIBUTE_NORMAL | FILE_FLAG_NO_BUFFERING | FILE_FLAG_OVERLAPPED;
                uint dwFlagsAndAttributes = FILE_ATTRIBUTE_DEVICE;

                IntPtr hTemplateFile = IntPtr.Zero;
                IntPtr hFile = CreateFile ( lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes,
                                                      dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile );
                Console.WriteLine ( hFile.ToString ( ) );
                uint fPageSize = lpSystemInfo.dwPageSize; // (4096) 
                uint aSize = fPageSize * 5;
                int aCount = 10;
                byte[ ] lpBuffer = new byte[ fPageSize ];
                IntPtr[ ] aBuffers = new IntPtr[ fPageSize ];
                IntPtr lpReserved = IntPtr.Zero;
                uint nNumberOfBytesToRead = lpSystemInfo.dwAllocationGranularity;
                uint lPerBufferPageCount = aSize / fPageSize;
                int pageing = ( int )lPerBufferPageCount;
                // aSegementArray -- output array
                FILE_SEGMENT_ELEMENT[ ] aSegementArray = new FILE_SEGMENT_ELEMENT[ nNumberOfBytesToRead + 1 ];

                FILE_SEGMENT_ELEMENT* lElements = stackalloc FILE_SEGMENT_ELEMENT[ ( aCount * pageing ) + 1 ];
                for ( int lElementIndex = 0; lElementIndex < aCount; lElementIndex++ )
                {
                    for ( int lPageIndex = 0; lPageIndex < lPerBufferPageCount; lPageIndex++ )
                    {
                        lElements[ ( lElementIndex * lPerBufferPageCount ) + lPageIndex ].Buffer =
                                        ( IntPtr )( ( uint )aBuffers[ lElementIndex ] + ( lPageIndex * fPageSize ) );
                    }
                }
                lElements[ ( aCount * lPerBufferPageCount ) ].Buffer = IntPtr.Zero;

                bool success = ReadFileScatter ( hFile, aSegementArray, nNumberOfBytesToRead, lpReserved, ref  lpOverlapped );
                //                int bytesRet = ReadFileScatter ( hFile, lElements, ( int )nNumberOfBytesToRead, lpReserved, pToOverlp );
                if ( success )
                {
                    Auxiliaries axil = new Auxiliaries ( );
                    axil.DebugPrintData ( lpBuffer, "" );
                }
            }
        }                                               // diskClone

        [System.Runtime.InteropServices.StructLayoutAttribute ( System.Runtime.InteropServices.LayoutKind.Explicit )]
        public struct ULARGE_INTEGER
        {
            /// Anonymous_652f900e_e9d5_4a81_ba95_5c3af2ba5157
            [System.Runtime.InteropServices.FieldOffsetAttribute ( 0 )]
            public Anonymous_652f900e_e9d5_4a81_ba95_5c3af2ba5157 Struct1;
            /// Anonymous_da3d5bb2_d7f6_4b49_a86f_df044e26e59a
            [System.Runtime.InteropServices.FieldOffsetAttribute ( 0 )]
            public Anonymous_da3d5bb2_d7f6_4b49_a86f_df044e26e59a u;
            /// ULONGLONG->unsigned __int64
            [System.Runtime.InteropServices.FieldOffsetAttribute ( 0 )]
            public ulong QuadPart;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute ( System.Runtime.InteropServices.LayoutKind.Sequential )]
        public struct Anonymous_652f900e_e9d5_4a81_ba95_5c3af2ba5157
        {
            /// DWORD->unsigned int
            public uint LowPart;
            /// DWORD->unsigned int
            public uint HighPart;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute ( System.Runtime.InteropServices.LayoutKind.Sequential )]
        public struct Anonymous_da3d5bb2_d7f6_4b49_a86f_df044e26e59a
        {
            /// DWORD->unsigned int
            public uint LowPart;
            /// DWORD->unsigned int
            public uint HighPart;
        }

        public partial class NativeMethods
        {
            /// Return Type: BOOL->int
            ///lpDirectoryName: LPCSTR->CHAR*
            ///lpFreeBytesAvailableToCaller: PULARGE_INTEGER->ULARGE_INTEGER*
            ///lpTotalNumberOfBytes: PULARGE_INTEGER->ULARGE_INTEGER*
            ///lpTotalNumberOfFreeBytes: PULARGE_INTEGER->ULARGE_INTEGER*
            [System.Runtime.InteropServices.DllImportAttribute ( "kernel32.dll", EntryPoint = "GetDiskFreeSpaceExA" )]
            [return: System.Runtime.InteropServices.MarshalAsAttribute ( System.Runtime.InteropServices.UnmanagedType.Bool )]
            public static extern bool GetDiskFreeSpaceExA (
                [System.Runtime.InteropServices.InAttribute ( )] [System.Runtime.InteropServices.MarshalAsAttribute ( System.Runtime.InteropServices.UnmanagedType.LPStr )] string lpDirectoryName,
                System.IntPtr lpFreeBytesAvailableToCaller, System.IntPtr lpTotalNumberOfBytes,
                System.IntPtr lpTotalNumberOfFreeBytes );
        }

        public partial class NativeMethods
        {
            /// Return Type: DWORD->unsigned int
            [System.Runtime.InteropServices.DllImportAttribute ( "kernel32.dll", EntryPoint = "GetLastError" )]
            public static extern uint GetLastError ( );
        }
    }

    static class GetDiskSize
    {
        public static uint METHOD_BUFFERED = 0;
        public static uint METHOD_IN_DIRECT = 1;
        public static uint METHOD_OUT_DIRECT = 2;
        public static uint METHOD_NEITHER = 3;
        public static uint FILE_ANY_ACCESS = 0;

        [Flags]
        public enum EFileAccess : uint
        {
            GenericRead = 0x80000000,
            GenericWrite = 0x40000000,
            GenericExecute = 0x20000000,
            GenericAll = 0x10000000
        }

        [Flags]
        public enum EFileShare : uint
        {
            None = 0x00000000,
            Read = 0x00000001,
            Write = 0x00000002,
            Delete = 0x00000004
        }

        public enum ECreationDisposition : uint
        {
            New = 1,
            CreateAlways = 2,
            OpenExisting = 3,
            OpenAlways = 4,
            TruncateExisting = 5
        }

        [Flags]
        public enum EFileAttributes : uint
        {
            Readonly = 0x00000001,
            Hidden = 0x00000002,
            System = 0x00000004,
            Directory = 0x00000010,
            Archive = 0x00000020,
            Device = 0x00000040,
            Normal = 0x00000080,
            Temporary = 0x00000100,
            SparseFile = 0x00000200,
            ReparsePoint = 0x00000400,
            Compressed = 0x00000800,
            Offline = 0x00001000,
            NotContentIndexed = 0x00002000,
            Encrypted = 0x00004000,
            Write_Through = 0x80000000,
            Overlapped = 0x40000000,
            NoBuffering = 0x20000000,
            RandomAccess = 0x10000000,
            SequentialScan = 0x08000000,
            DeleteOnClose = 0x04000000,
            BackupSemantics = 0x02000000,
            PosixSemantics = 0x01000000,
            OpenReparsePoint = 0x00200000,
            OpenNoRecall = 0x00100000,
            FirstPipeInstance = 0x00080000
        }


        static uint CTL_CODE ( uint deviceType, uint function, uint method, uint access )
        {
            return ( ( deviceType ) << 16 ) | ( ( access ) << 14 ) | ( ( function ) << 2 ) | ( method );
        }

        [DllImport ( "Kernel32.dll", SetLastError = true, CharSet = CharSet.Auto )]
        public static extern Microsoft.Win32.SafeHandles.SafeFileHandle CreateFile (
            string fileName,
            [MarshalAs ( UnmanagedType.U4 )] EFileAccess fileAccess,
            [MarshalAs ( UnmanagedType.U4 )] EFileShare fileShare,
            IntPtr securityAttributes,
            [MarshalAs ( UnmanagedType.U4 )] FileMode creationDisposition,
            [MarshalAs ( UnmanagedType.U4 )] EFileAttributes flags,
            IntPtr template );

        [DllImport ( "kernel32.dll", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Auto )]
        public static extern bool DeviceIoControl (
            Microsoft.Win32.SafeHandles.SafeFileHandle hDevice,
            uint dwIoControlCode,
            IntPtr lpInBuffer,
            uint nInBufferSize,
            out Int64 lpOutBuffer,
            uint nOutBufferSize,
            out uint lpBytesReturned,
            IntPtr lpOverlapped );

        static uint IOCTL_DISK_BASE = 0x00000007;
 //       static uint FILE_READ_ACCESS = 0x00000001;

        public static uint IOCTL_DISK_GET_LENGTH_INFO = CTL_CODE ( IOCTL_DISK_BASE,
                                    0x0017,
                                    METHOD_BUFFERED,
                                    1 );

        public static Int64 GetSize ( )
        {
            Int64 DriveSize = 0;
            Microsoft.Win32.SafeHandles.SafeFileHandle hnd = CreateFile ( "\\\\.\\PhysicalDrive0",
                    EFileAccess.GenericRead,
                    EFileShare.Read,
                    IntPtr.Zero,
                    FileMode.Open,
                    EFileAttributes.Device,
                    IntPtr.Zero );            // do not copy file attributes   

            if ( !hnd.IsInvalid )
            {
                if ( DeviceIoControl ( hnd, IOCTL_DISK_GET_LENGTH_INFO, IntPtr.Zero, 0, out DriveSize, 8, out uint BytesReturned, IntPtr.Zero ) )
                {
                    return DriveSize;
                }
            }
            return DriveSize;
        }                                               // GetSize
    }

    class Ioctls
    {
        static uint FILE_DEVICE_DISK = 0x00000007;
        static uint IOCTL_DISK_BASE = FILE_DEVICE_DISK;
        static uint METHOD_BUFFERED = 0x00000000;
        static uint FILE_ANY_ACCESS = 0x00000000;
        static uint FILE_READ_ACCESS = 0x00000001;
 //       static uint FILE_WRITE_ACCESS = 0x00000002;
        static uint FILE_DEVICE_FILE_SYSTEM = 0x00000009;
        static uint METHOD_NEITHER = 0x00000003;

        public static uint IOCTL_DISK_GET_LENGTH_INFO = CTL_CODE ( IOCTL_DISK_BASE,
                                     0x0017,
                                     METHOD_BUFFERED,
                                     FILE_READ_ACCESS );

        public static uint IOCTL_DISK_GET_DRIVE_GEOMETRY_EX = CTL_CODE ( IOCTL_DISK_BASE,
                                     0x0028,
                                     METHOD_BUFFERED,
                                     FILE_ANY_ACCESS );

        public static uint FSCTL_ALLOW_EXTENDED_DASD_IO = CTL_CODE ( IOCTL_DISK_BASE,
                                    32,
                                    METHOD_NEITHER,
                                    FILE_ANY_ACCESS );

        public static uint FSCTL_LOCK_VOLUME = CTL_CODE ( FILE_DEVICE_FILE_SYSTEM,
                                    6,
                                    METHOD_BUFFERED,
                                    FILE_ANY_ACCESS );

        static uint CTL_CODE ( uint deviceType, uint function, uint method, uint access )
        {
            return ( ( deviceType ) << 16 ) | ( ( access ) << 14 ) | ( ( function ) << 2 ) | ( method );
        }

        /*
            HID Class Driver IOCTLs
            Topic	Description
            IOCTL_GET_NUM_DEVICE_INPUT_BUFFERS
            // The IOCTL_GET_NUM_DEVICE_INPUT_BUFFERS request obtains the size of the input report queue for a top-level collection.
            IOCTL_GET_PHYSICAL_DESCRIPTOR
            // The IOCTL_GET_PHYSICAL_DESCRIPTOR request obtains the physical descriptor of a top-level collection.
            IOCTL_HID_DEVICERESET_NOTIFICATION
            // The IOCTL_HID_DEVICERESET_NOTIFICATION request is sent by the HID client driver to HID class driver to wait for a device-initiated reset event.
            IOCTL_HID_DISABLE_SECURE_READ
            // The IOCTL_HID_DISABLE_SECURE_READ request cancels an IOCTL_HID_ENABLE_SECURE_READ request for a HID collection.
            IOCTL_HID_ENABLE_SECURE_READ
            // The IOCTL_HID_ENABLE_SECURE_READ request enables a secure read for open files of a HID collection.
            IOCTL_HID_ENABLE_WAKE_ON_SX
            // The IOCTL_HID_ENABLE_WAKE_ON_SX request is used to indicate the requirement for a device to be able to wake from system sleep.
            IOCTL_HID_FLUSH_QUEUE
            // The IOCTL_HID_FLUSH_QUEUE request dequeues all of the unparsed input reports from a top-level collection's input report queue.
            IOCTL_HID_GET_COLLECTION_DESCRIPTOR
            // The IOCTL_HID_GET_COLLECTION_DESCRIPTOR request obtains a top-level collection's preparsed data, which the HID class driver extracted from the physical device's report descriptor during device initialization.
            IOCTL_HID_GET_COLLECTION_INFORMATION
            // The IOCTL_HID_GET_COLLECTION_INFORMATION request obtains a top-level collection's  HID_COLLECTION_INFORMATION structure.
            IOCTL_HID_GET_DRIVER_CONFIG
            // The IOCTL_HID_GET_DRIVER_CONFIG request retrieves the driver configuration.
            IOCTL_HID_GET_FEATURE
            // The IOCTL_HID_GET_FEATURE request returns a feature report associated with a top-level collection.
            IOCTL_HID_GET_HARDWARE_ID
            // The IOCTL_HID_GET_HARDWARE_ID request obtains the Plug and Play hardware ID of a top-level collection.
            IOCTL_HID_GET_INDEXED_STRING
            // The IOCTL_HID_GET_INDEXED_STRING request obtains a specified embedded string from a top-level collection.
            IOCTL_HID_GET_INPUT_REPORT
            // The IOCTL_HID_GET_INPUT_REPORT request obtains an input report from a top-level collection.
            IOCTL_HID_GET_MANUFACTURER_STRING
            // The IOCTL_HID_GET_MANUFACTURER_STRING request obtains a top-level collection's embedded string that identifies the manufacturer of the device.
            IOCTL_HID_GET_MS_GENRE_DESCRIPTOR
            // The IOCTL_HID_GET_MS_GENRE_DESCRIPTOR request is used for retrieving the genre descriptor for the device.
            IOCTL_HID_GET_POLL_FREQUENCY_MSEC
            // The IOCTL_HID_GET_POLL_FREQUENCY_MSEC request obtains the current polling frequency, in milliseconds, of a top-level collection.
            IOCTL_HID_GET_PRODUCT_STRING
            // The IOCTL_HID_GET_PRODUCT_STRING request obtains a top-level collection's embedded string that identifies the manufacturer's product. 
            The retrieved string is a NULL-terminated wide character string in a human-readable format.

            For general information about HIDClass devices, see HID Collections.
            IOCTL_HID_GET_SERIALNUMBER_STRING
            // The IOCTL_HID_GET_SERIALNUMBER_STRING request obtains a top-level collection's embedded string that identifies the device's serial number.
            IOCTL_HID_SET_DRIVER_CONFIG
            // The IOCTL_HID_SET_DRIVER_CONFIG request sets the driver configuration.
            IOCTL_HID_SET_FEATURE
            // The IOCTL_HID_SET_FEATURE request sends a feature report to a top-level collection.
            // For general information about HIDClass devices, see HID Collections.
            IOCTL_HID_SET_OUTPUT_REPORT	
            // The IOCTL_HID_SET_OUTPUT_REPORT request sends an output report to a top-level collection.
            IOCTL_HID_SET_POLL_FREQUENCY_MSEC
	

       The IOCTL_HID_SET_POLL_FREQUENCY_MSEC request sets the polling frequency, in milliseconds, for a top-level collection.
       User-mode applications or kernel-mode drivers that perform irregular, opportunistic reads on a polled device must furnish a polling interval of zero. 
       In such cases, IOCTL_HID_SET_POLL_FREQUENCY_MSEC does not actually change the polling frequency of the device; but if the report data is not stale 
       when it is read, the read is completed immediately with the latest report data for the indicated collection. If the report data is stale, 
       it is refreshed immediately, without waiting for the expiration of the polling interval, and the read is completed with the new data.
       If the value for the polling interval that is provided in the IRP is not zero, it must be >= MIN_POLL_INTERVAL_MSEC and <= MAX_POLL_INTERVAL_MSEC.
       Polling may be limited if there are multiple top-level collections.
       For general information about HIDClass devices, see HID Collections.

       IOCTL_HID_SET_S0_IDLE_TIMEOUT
       The IOCTL_HID_SET_S0_IDLE_TIMEOUT request is used by a client to inform the HID class driver about the client's preferred idle timeout value.
       IOCTL_SET_NUM_DEVICE_INPUT_BUFFERS
       // The IOCTL_SET_NUM_DEVICE_INPUT_BUFFERS request sets the number of buffers for the input report queue of a top-level collection.

       Each input report queue is implemented as a ring buffer. If a collection transmits data to the HID class driver faster than the driver can read it, 
       some of the data may be lost. To prevent this type of loss, you can use an IOCTL_SET_NUM_DEVICE_INPUT_BUFFERS request to adjust the number of buffers 
       that the input report queue contains. The HID class driver requires a minimum of two input buffers. On Windows 2000, the maximum number of input buffers 
       that the HID class driver supports is 200, and on Windows XP and later, the maximum number of input buffers that the HID class driver supports is 512. 
       The default number of input buffers is 32.

       For general information about HIDClass devices, see HID Collections. 
  */

    }


}

public sealed class SizeT
{
    // https://blogs.msdn.microsoft.com/jaredpar/2006/04/12/pinvoke-with-32-and-64-bit-machines/

    private ulong m_value;

    public ulong Value
    {
        get { return m_value; }
        set { m_value = value; }
    }

    public SizeT(ulong val)
    {
        m_value = val;
    }

    [SuppressMessage("Microsoft.Usage", "CA2225")]
    public static implicit operator SizeT(ulong value)
    {
        return new SizeT(value);
    }

    [SuppressMessage("Microsoft.Usage", "CA2225")]
    public static implicit operator ulong(SizeT value)
    {
        return value.Value;
    }
}

public sealed class SizeTMarshaler : ICustomMarshaler
{
    [SuppressMessage("Microsoft.Usage", "CA1801", Justification = "data parameter is a hidden requirement of the API")]
    public static ICustomMarshaler GetInstance(string data)
    {
        return new SizeTMarshaler();
    }

    #region ICustomMarshaler Members

    public void CleanUpManagedData(object ManagedObj)
    {
        // Nothing to do
    }

    public void CleanUpNativeData(IntPtr pNativeData)
    {
        Marshal.FreeCoTaskMem(pNativeData);
    }

    public int GetNativeDataSize()
    {
        return IntPtr.Size;
    }

    public IntPtr MarshalManagedToNative(object ManagedObj)
    {
        SizeT value = (SizeT)ManagedObj;
        IntPtr ptr = Marshal.AllocCoTaskMem(IntPtr.Size);
        checked
        {
      //      IntPtr ptr = Marshal.AllocCoTaskMem(IntPtr.Size);
            if (IntPtr.Size == 4)
            {
                Marshal.StructureToPtr((uint)value.Value, ptr, true);
            }
            else if (IntPtr.Size == 8)
            {
                Marshal.StructureToPtr(value.Value, ptr, true);
            }
            else
            {
                throw new ArgumentException("Invalid Pointer Size");
            }
        }
        return ptr;
    }

    public object MarshalNativeToManaged(IntPtr pNativeData)
    {
        if (IntPtr.Size == 4)
        {
            uint val = (uint)Marshal.PtrToStructure(pNativeData, typeof(uint));
            return new SizeT(val);
        }
        else if (IntPtr.Size == 8)
        {
            ulong val = (ulong)Marshal.PtrToStructure(pNativeData, typeof(ulong));
            return new SizeT(val);
        }
        else
        {
            throw new ArgumentException("Invalid Pointer Size");
        }
    }
    #endregion
}







