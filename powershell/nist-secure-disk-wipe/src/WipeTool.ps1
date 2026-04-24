#Requires -RunAsAdministrator
<#
///////////////////////////////////////////////////////////////////////////////
//  BLCKSNAKE SECURITY TOOLS
//  -----------------------------------------------------------------------
//  SCRIPT  : WipeTool.ps1
//  AUTHOR  : Jeysson Rostran  (@BLCKSNAKE)
//  VERSION : 2.0.0
//  DATE    : 2026-04-24
//  PURPOSE : NIST SP 800-88r2 compliant secure disk wipe for WinPE
//  USAGE   : Boots automatically from SecureWipe USB
//
//  METHODS : Clear (Sec.3.1.1) | Purge (Sec.3.1.2) | NVMe Sanitize
//  VERIFY  : 256-sector random sampling (Sec.4.5.1)
//  REPORT  : Certificate of Sanitization - Appendix C / Sec.4.6
//
//  LEGAL   : BLCKSNAKE Security Tools - MIT License
//            https://blcksnake.com/security
///////////////////////////////////////////////////////////////////////////////
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---- Embedded C# disk operations --------------------------------------------
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

public static class DiskOps
{
    // Win32 constants
    const uint GENERIC_READ                     = 0x80000000;
    const uint GENERIC_WRITE                    = 0x40000000;
    const uint FILE_SHARE_READ                  = 0x00000001;
    const uint FILE_SHARE_WRITE                 = 0x00000002;
    const uint OPEN_EXISTING                    = 3;
    const uint FILE_FLAG_WRITE_THROUGH          = 0x80000000;
    const uint FILE_FLAG_NO_BUFFERING           = 0x20000000;

    const uint IOCTL_ATA_PASS_THROUGH_DIRECT    = 0x4D034;
    const uint IOCTL_STORAGE_QUERY_PROPERTY     = 0x002D1400;
    const uint IOCTL_DISK_GET_DRIVE_GEOMETRY_EX = 0x000700A0;
    const uint IOCTL_STORAGE_PROTOCOL_COMMAND   = 0x002D5500;

    // ATA pass-through flags
    const ushort ATA_FLAGS_DRDY_REQUIRED        = 0x0001;
    const ushort ATA_FLAGS_DATA_IN              = 0x0002;
    const ushort ATA_FLAGS_DATA_OUT             = 0x0004;
    const ushort ATA_FLAGS_48BIT_COMMAND        = 0x0008;

    // ---- P/Invoke ------------------------------------------------------------
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    static extern SafeFileHandle CreateFile(
        string lpFileName, uint dwDesiredAccess, uint dwShareMode,
        IntPtr lpSecurityAttributes, uint dwCreationDisposition,
        uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool DeviceIoControl(
        SafeFileHandle hDevice, uint dwIoControlCode,
        IntPtr lpInBuffer, uint nInBufferSize,
        IntPtr lpOutBuffer, uint nOutBufferSize,
        out uint lpBytesReturned, IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool WriteFile(
        SafeFileHandle hFile, byte[] lpBuffer, uint nNumberOfBytesToWrite,
        out uint lpNumberOfBytesWritten, IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetFilePointerEx(
        SafeFileHandle hFile, long liDistanceToMove,
        out long lpNewFilePointer, uint dwMoveMethod);

    // ---- ATA structures -----------------------------------------------------
    [StructLayout(LayoutKind.Sequential)]
    struct ATA_PASS_THROUGH_DIRECT
    {
        public ushort Length;
        public ushort AtaFlags;
        public byte   PathId;
        public byte   TargetId;
        public byte   Lun;
        public byte   ReservedAsWords;
        public uint   DataTransferLength;
        public uint   TimeOutValue;
        public IntPtr DataBuffer;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public byte[] PreviousTaskFile;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public byte[] CurrentTaskFile; // [0]=Feat [1]=Count [2]=LBALo [3]=LBAMid [4]=LBAHi [5]=Dev [6]=Cmd [7]=Rsvd
    }

    [StructLayout(LayoutKind.Sequential)]
    struct DISK_GEOMETRY_EX
    {
        public long  Cylinders;
        public uint  MediaType;
        public uint  TracksPerCylinder;
        public uint  SectorsPerTrack;
        public uint  BytesPerSector;
        public long  DiskSize;
        public ulong Data;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct STORAGE_PROPERTY_QUERY
    {
        public uint PropertyId;   // 0 = StorageDeviceProperty
        public uint QueryType;    // 0 = PropertyStandardQuery
        public byte AdditionalParameters;
    }

    // NVMe protocol command constants
    const uint STORAGE_PROTOCOL_STRUCTURE_VERSION      = 1;
    const uint STORAGE_PROTOCOL_TYPE_NVME              = 3;
    const uint NVME_COMMAND_LENGTH                     = 64;
    const int  STORAGE_PROTOCOL_COMMAND_HEADER_SIZE    = 108;

    // ---- Public API ---------------------------------------------------------

    public static SafeFileHandle OpenDisk(int index, bool writeAccess = false)
    {
        uint access = GENERIC_READ;
        if (writeAccess) access |= GENERIC_WRITE;
        var h = CreateFile(
            string.Format(@"\\.\PhysicalDrive{0}", index),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            IntPtr.Zero, OPEN_EXISTING,
            FILE_FLAG_WRITE_THROUGH | FILE_FLAG_NO_BUFFERING,
            IntPtr.Zero);
        if (h.IsInvalid)
            throw new IOException("Cannot open PhysicalDrive" + index +
                " (error " + Marshal.GetLastWin32Error() + ")");
        return h;
    }

    public static long GetDiskSize(SafeFileHandle h)
    {
        int sz = Marshal.SizeOf(typeof(DISK_GEOMETRY_EX));
        IntPtr buf = Marshal.AllocHGlobal(sz + 64);
        try {
            uint returned;
            if (!DeviceIoControl(h, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
                    IntPtr.Zero, 0, buf, (uint)(sz + 64), out returned, IntPtr.Zero))
                throw new IOException("IOCTL_DISK_GET_DRIVE_GEOMETRY_EX failed: " +
                    Marshal.GetLastWin32Error());
            var geo = (DISK_GEOMETRY_EX)Marshal.PtrToStructure(buf, typeof(DISK_GEOMETRY_EX));
            return geo.DiskSize;
        } finally { Marshal.FreeHGlobal(buf); }
    }

    // Returns raw 512-byte IDENTIFY DEVICE response
    public static byte[] AtaIdentify(SafeFileHandle h)
    {
        byte[] data = new byte[512];
        IntPtr dataBuf = Marshal.AllocHGlobal(512);
        try {
            Marshal.Copy(new byte[512], 0, dataBuf, 512);
            var cmd = new ATA_PASS_THROUGH_DIRECT();
            cmd.Length = (ushort)Marshal.SizeOf(typeof(ATA_PASS_THROUGH_DIRECT));
            cmd.AtaFlags = (ushort)(ATA_FLAGS_DRDY_REQUIRED | ATA_FLAGS_DATA_IN);
            cmd.DataTransferLength = 512;
            cmd.TimeOutValue = 30;
            cmd.DataBuffer = dataBuf;
            cmd.PreviousTaskFile = new byte[8];
            cmd.CurrentTaskFile = new byte[8];
            cmd.CurrentTaskFile[1] = 1;     // sector count = 1
            cmd.CurrentTaskFile[5] = 0xA0;  // device: LBA mode
            cmd.CurrentTaskFile[6] = 0xEC;  // IDENTIFY DEVICE

            int cmdSz = Marshal.SizeOf(typeof(ATA_PASS_THROUGH_DIRECT));
            IntPtr cmdBuf = Marshal.AllocHGlobal(cmdSz);
            try {
                Marshal.StructureToPtr(cmd, cmdBuf, false);
                uint returned;
                if (!DeviceIoControl(h, IOCTL_ATA_PASS_THROUGH_DIRECT,
                        cmdBuf, (uint)cmdSz, cmdBuf, (uint)cmdSz, out returned, IntPtr.Zero))
                    throw new IOException("ATA IDENTIFY failed: " + Marshal.GetLastWin32Error());
            } finally { Marshal.FreeHGlobal(cmdBuf); }
            Marshal.Copy(dataBuf, data, 0, 512);
            return data;
        } finally { Marshal.FreeHGlobal(dataBuf); }
    }

    static bool SendAtaCommand(SafeFileHandle h, byte[] taskFile,
        byte[] dataOut = null, int timeoutSec = 30)
    {
        ushort flags = ATA_FLAGS_DRDY_REQUIRED;
        IntPtr dataBuf = IntPtr.Zero;
        uint dataLen = 0;

        if (dataOut != null) {
            flags |= ATA_FLAGS_DATA_OUT;
            dataLen = (uint)dataOut.Length;
            dataBuf = Marshal.AllocHGlobal(dataOut.Length);
            Marshal.Copy(dataOut, 0, dataBuf, dataOut.Length);
        }

        var cmd = new ATA_PASS_THROUGH_DIRECT();
        cmd.Length = (ushort)Marshal.SizeOf(typeof(ATA_PASS_THROUGH_DIRECT));
        cmd.AtaFlags = flags;
        cmd.DataTransferLength = dataLen;
        cmd.TimeOutValue = (uint)timeoutSec;
        cmd.DataBuffer = dataBuf;
        cmd.PreviousTaskFile = new byte[8];
        cmd.CurrentTaskFile = taskFile;

        int cmdSz = Marshal.SizeOf(typeof(ATA_PASS_THROUGH_DIRECT));
        IntPtr cmdBuf = Marshal.AllocHGlobal(cmdSz);
        bool ok = false;
        try {
            Marshal.StructureToPtr(cmd, cmdBuf, false);
            uint returned;
            ok = DeviceIoControl(h, IOCTL_ATA_PASS_THROUGH_DIRECT,
                     cmdBuf, (uint)cmdSz, cmdBuf, (uint)cmdSz, out returned, IntPtr.Zero);
            if (!ok) throw new IOException("ATA cmd 0x" + taskFile[6].ToString("X2") +
                " failed: " + Marshal.GetLastWin32Error());
        } finally {
            Marshal.FreeHGlobal(cmdBuf);
            if (dataBuf != IntPtr.Zero) Marshal.FreeHGlobal(dataBuf);
        }
        return ok;
    }

    // ATA SECURITY SET PASSWORD -- sets NULL user password (all-zero buffer)
    public static void AtaSecuritySetPassword(SafeFileHandle h)
    {
        byte[] data = new byte[512]; // word 0 = 0 means: user password, high security level
        var tf = new byte[8];
        tf[1] = 1;
        tf[5] = 0xA0;
        tf[6] = 0xF1;  // SECURITY SET PASSWORD
        SendAtaCommand(h, tf, data, 30);
    }

    // ATA SECURITY ERASE PREPARE (no-data command, must precede ERASE UNIT)
    public static void AtaSecurityErasePrepare(SafeFileHandle h)
    {
        var tf = new byte[8];
        tf[5] = 0xA0;
        tf[6] = 0xF3;  // SECURITY ERASE PREPARE
        SendAtaCommand(h, tf, null, 30);
    }

    // ATA SECURITY ERASE UNIT
    // enhanced=true -> Enhanced Erase (NIST Purge); false -> Normal Erase (NIST Clear equivalent)
    public static void AtaSecurityEraseUnit(SafeFileHandle h, bool enhanced, int timeoutSec = 21600)
    {
        byte[] data = new byte[512]; // same NULL password used during SET PASSWORD
        if (enhanced) data[0] = 0x02; // bit 1 = enhanced erase
        var tf = new byte[8];
        tf[0] = (byte)(enhanced ? 1 : 0); // features: 1 = enhanced
        tf[1] = 1;
        tf[5] = 0xA0;
        tf[6] = 0xF4;  // SECURITY ERASE UNIT
        SendAtaCommand(h, tf, data, timeoutSec);
    }

    // ATA SANITIZE DEVICE EXT (48-bit command, 0xB4)
    // cryptoScramble=true -> feature 0x0011 (NIST Purge - crypto)
    // cryptoScramble=false -> feature 0x0012 (NIST Purge - block erase)
    public static void AtaSanitize(SafeFileHandle h, bool cryptoScramble, int timeoutSec = 21600)
    {
        ushort feature = cryptoScramble ? (ushort)0x0011 : (ushort)0x0012;
        var tf = new byte[8];
        tf[0] = (byte)(feature & 0xFF);   // features low
        tf[1] = 1;
        tf[5] = 0x40;                      // device: 48-bit LBA
        tf[6] = 0xB4;                      // SANITIZE DEVICE EXT
        ushort ataf = (ushort)(ATA_FLAGS_DRDY_REQUIRED | ATA_FLAGS_48BIT_COMMAND);

        var cmd = new ATA_PASS_THROUGH_DIRECT();
        cmd.Length = (ushort)Marshal.SizeOf(typeof(ATA_PASS_THROUGH_DIRECT));
        cmd.AtaFlags = ataf;
        cmd.DataTransferLength = 0;
        cmd.TimeOutValue = (uint)timeoutSec;
        cmd.DataBuffer = IntPtr.Zero;
        cmd.PreviousTaskFile = new byte[8];
        cmd.PreviousTaskFile[0] = (byte)((feature >> 8) & 0xFF); // features high
        cmd.CurrentTaskFile = tf;

        int cmdSz = Marshal.SizeOf(typeof(ATA_PASS_THROUGH_DIRECT));
        IntPtr cmdBuf = Marshal.AllocHGlobal(cmdSz);
        try {
            Marshal.StructureToPtr(cmd, cmdBuf, false);
            uint returned;
            if (!DeviceIoControl(h, IOCTL_ATA_PASS_THROUGH_DIRECT,
                    cmdBuf, (uint)cmdSz, cmdBuf, (uint)cmdSz, out returned, IntPtr.Zero))
                throw new IOException("ATA SANITIZE failed: " + Marshal.GetLastWin32Error());
        } finally { Marshal.FreeHGlobal(cmdBuf); }
    }

    // NVMe Sanitize via IOCTL_STORAGE_PROTOCOL_COMMAND
    // sanact: 1=Crypto Erase, 2=Block Erase (NIST SP 800-88r2 Sec.3.1.2)
    public static void NvmeSanitize(SafeFileHandle h, byte sanact, int timeoutSec = 21600)
    {
        int totalSize = STORAGE_PROTOCOL_COMMAND_HEADER_SIZE + (int)NVME_COMMAND_LENGTH;
        IntPtr buf = Marshal.AllocHGlobal(totalSize);
        try {
            for (int i = 0; i < totalSize; i++) Marshal.WriteByte(buf, i, 0);

            int off = 0;
            Marshal.WriteInt32(buf, off, (int)STORAGE_PROTOCOL_STRUCTURE_VERSION); off += 4;
            Marshal.WriteInt32(buf, off, totalSize); off += 4;
            Marshal.WriteInt32(buf, off, (int)STORAGE_PROTOCOL_TYPE_NVME); off += 4;
            Marshal.WriteInt32(buf, off, 0); off += 4; // Flags
            Marshal.WriteInt32(buf, off, 0); off += 4; // ReturnStatus
            Marshal.WriteInt32(buf, off, 0); off += 4; // ErrorCode
            Marshal.WriteInt32(buf, off, (int)NVME_COMMAND_LENGTH); off += 4; // CommandLength
            Marshal.WriteInt32(buf, off, 0); off += 4; // ErrorInfoLength
            Marshal.WriteInt32(buf, off, 0); off += 4; // DataToDeviceTransferLength
            Marshal.WriteInt32(buf, off, 0); off += 4; // DataFromDeviceTransferLength
            Marshal.WriteInt32(buf, off, timeoutSec); off += 4;
            Marshal.WriteInt32(buf, off, 0); off += 4; // ErrorInfoOffset
            Marshal.WriteInt32(buf, off, 0); off += 4; // DataToDeviceBufferOffset
            Marshal.WriteInt32(buf, off, 0); off += 4; // DataFromDeviceBufferOffset
            Marshal.WriteInt32(buf, off, 0); off += 4; // CommandSpecific
            Marshal.WriteInt32(buf, off, 0); off += 4; // Reserved0
            Marshal.WriteInt32(buf, off, 0); off += 4; // FixedProtocolReturnData
            off += 12; // Reserved1[3]
            // Command[] starts at off (offset 108)
            Marshal.WriteByte(buf, off + 0, 0x84);          // NVMe Sanitize opcode
            Marshal.WriteByte(buf, off + 1, 0x00);          // Flags
            Marshal.WriteInt16(buf, off + 2, 0);            // CID
            Marshal.WriteInt32(buf, off + 4, -1);           // NSID = all namespaces (0xFFFFFFFF)
            Marshal.WriteInt32(buf, off + 40, (int)sanact); // CDW10: SANACT

            uint returned;
            if (!DeviceIoControl(h, IOCTL_STORAGE_PROTOCOL_COMMAND,
                    buf, (uint)totalSize, buf, (uint)totalSize, out returned, IntPtr.Zero))
                throw new IOException("NVMe Sanitize failed: " + Marshal.GetLastWin32Error());
        } finally { Marshal.FreeHGlobal(buf); }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool ReadFile(
        SafeFileHandle hFile, byte[] lpBuffer, uint nNumberOfBytesToRead,
        out uint lpNumberOfBytesRead, IntPtr lpOverlapped);

    // Verify disk contains only zeros by sampling random sectors (NIST 800-88r2 s4.5.1)
    // Returns count of non-zero sectors found (0 = verified clean)
    public static int VerifyZeros(int driveIndex, long diskSizeBytes, int sampleCount,
        Action<double> progressCallback)
    {
        var    rng     = new Random(42);
        long   sectors = diskSizeBytes / 512;
        int    failed  = 0;
        byte[] buf     = new byte[512];

        var h = CreateFile(
            string.Format(@"\\.\PhysicalDrive{0}", driveIndex),
            GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
            IntPtr.Zero, OPEN_EXISTING, FILE_FLAG_NO_BUFFERING, IntPtr.Zero);
        if (h.IsInvalid)
            throw new IOException("Cannot open drive for verify: " + Marshal.GetLastWin32Error());

        try {
            for (int i = 0; i < sampleCount; i++) {
                // Pick a random sector aligned to 512 bytes
                long sector = (long)(rng.NextDouble() * (sectors - 1));
                long newPos;
                SetFilePointerEx(h, sector * 512, out newPos, 0);

                uint bytesRead;
                if (ReadFile(h, buf, 512, out bytesRead, IntPtr.Zero) && bytesRead == 512) {
                    for (int b = 0; b < 512; b++) {
                        if (buf[b] != 0) { failed++; break; }
                    }
                }
                if (progressCallback != null)
                    progressCallback((double)(i + 1) / sampleCount * 100.0);
            }
        } finally { h.Dispose(); }
        return failed;
    }

    // Overwrite entire disk with zeros; progressCallback(pct, mbps) called every 256 MiB
    public static void OverwriteWithZeros(int driveIndex, long diskSizeBytes,
        Action<double, double> progressCallback, int passes = 1)
    {
        const int CHUNK = 64 * 1024 * 1024; // 64 MiB
        byte[] zeros = new byte[CHUNK];

        var h = CreateFile(
            string.Format(@"\\.\PhysicalDrive{0}", driveIndex),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            IntPtr.Zero, OPEN_EXISTING,
            FILE_FLAG_WRITE_THROUGH | FILE_FLAG_NO_BUFFERING,
            IntPtr.Zero);
        if (h.IsInvalid)
            throw new IOException("Cannot open drive for writing: " + Marshal.GetLastWin32Error());

        try {
            for (int pass = 0; pass < passes; pass++) {
                long newPos;
                SetFilePointerEx(h, 0, out newPos, 0);

                long written = 0;
                var sw = System.Diagnostics.Stopwatch.StartNew();
                long lastReport = 0;

                while (written < diskSizeBytes) {
                    long remaining = diskSizeBytes - written;
                    uint toWrite = (uint)Math.Min(CHUNK, remaining);
                    toWrite = (toWrite / 512) * 512; // sector-align
                    if (toWrite == 0) break;

                    uint bytesWritten;
                    if (!WriteFile(h, zeros, toWrite, out bytesWritten, IntPtr.Zero))
                        throw new IOException("WriteFile failed at offset " + written +
                            ": " + Marshal.GetLastWin32Error());
                    written += bytesWritten;

                    if (written - lastReport >= 256L * 1024 * 1024) {
                        double pct  = (double)(pass * diskSizeBytes + written) /
                                      (passes * diskSizeBytes) * 100.0;
                        double mbps = written / 1024.0 / 1024.0 / sw.Elapsed.TotalSeconds;
                        progressCallback(pct, mbps);
                        lastReport = written;
                    }
                }
            }
        } finally { h.Dispose(); }
    }

    // Query STORAGE_DEVICE_PROPERTY (vendor, model, serial, bus type)
    public static DriveInfo QueryDeviceProperty(int driveIndex)
    {
        var result = new DriveInfo();
        var h = CreateFile(
            string.Format(@"\\.\PhysicalDrive{0}", driveIndex),
            GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
            IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
        if (h.IsInvalid) return result;

        try {
            int bufSz = 4096;
            IntPtr outBuf = Marshal.AllocHGlobal(bufSz);
            var query = new STORAGE_PROPERTY_QUERY { PropertyId = 0, QueryType = 0 };
            int querySz = Marshal.SizeOf(typeof(STORAGE_PROPERTY_QUERY));
            IntPtr qBuf = Marshal.AllocHGlobal(querySz);
            try {
                Marshal.StructureToPtr(query, qBuf, false);
                uint returned;
                if (!DeviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY,
                        qBuf, (uint)querySz, outBuf, (uint)bufSz, out returned, IntPtr.Zero))
                    return result;

                // STORAGE_DEVICE_DESCRIPTOR offsets (from MSDN)
                // +15 DWORD VendorIdOffset
                // +19 DWORD ProductIdOffset
                // +27 DWORD SerialNumberOffset
                // +31 BYTE  BusType
                int vendorOff  = Marshal.ReadInt32(outBuf, 15);
                int productOff = Marshal.ReadInt32(outBuf, 19);
                int serialOff  = Marshal.ReadInt32(outBuf, 27);
                int busType    = Marshal.ReadByte(outBuf, 31);

                result.VendorId = vendorOff  > 0 ? ReadNullTermAnsi(outBuf, vendorOff,  bufSz) : "";
                result.Model    = productOff > 0 ? ReadNullTermAnsi(outBuf, productOff, bufSz) : "";
                result.Serial   = serialOff  > 0 ? ReadNullTermAnsi(outBuf, serialOff,  bufSz) : "";
                result.BusType  = busType;
            } finally {
                Marshal.FreeHGlobal(outBuf);
                Marshal.FreeHGlobal(qBuf);
            }
        } finally { h.Dispose(); }
        return result;
    }

    static string ReadNullTermAnsi(IntPtr buf, int offset, int maxLen)
    {
        var sb = new StringBuilder();
        for (int i = offset; i < maxLen; i++) {
            byte b = Marshal.ReadByte(buf, i);
            if (b == 0) break;
            sb.Append((char)b);
        }
        return sb.ToString().Trim();
    }
}

public class DriveInfo
{
    public string VendorId = "";
    public string Model    = "";
    public string Serial   = "";
    public int    BusType  = 0; // 3=ATA/SATA 7=USB 9=NVMe 11=SAS
}
'@ -Language CSharp

# ---- Console theme (BLCKSNAKE brand: yellow #FDB913 on black) ---------------
function Set-BrandTheme {
    try {
        $h = $Host.UI.RawUI
        $h.BackgroundColor = "Black"
        $h.ForegroundColor = "Gray"
        Clear-Host
    } catch {}
}

# ---- Console helpers ---------------------------------------------------------
function Write-Banner {
    Set-BrandTheme
    # BLCKSNAKE "ANSI Shadow" block art - base64 encoded so source stays pure ASCII
    $b64 = "IOKWiOKWiOKWiOKWiOKWiOKWiOKVlyDilojilojilZEgICAgICDilojilojilojilojilojilojilZfilojilojilZEgIOKWiOKWiOKVkeKWiOKWiOKWiOKWiOKWiOKWiOKWiOKVl+KWiOKWiOKWiOKVlyAgIOKWiOKWiOKVkSDilojilojilojilojilojilZcg4paI4paI4pWRICDilojilojilZHilojilojilojilojilojilojilojilZcKIOKWiOKWiOKVlOKVkOKVkOKWiOKWiOKVl+KWiOKWiOKVkSAgICAg4paI4paI4pWU4pWQ4pWQ4pWQ4pWQ4pWd4paI4paI4pWRIOKWiOKWiOKVlOKVneKWiOKWiOKVlOKVkOKVkOKVkOKVkOKVneKWiOKWiOKWiOKWiOKVlyAg4paI4paI4pWR4paI4paI4pWU4pWQ4pWQ4paI4paI4pWX4paI4paI4pWRIOKWiOKWiOKVlOKVneKWiOKWiOKVlOKVkOKVkOKVkOKVkOKVnQog4paI4paI4paI4paI4paI4paI4pWU4pWd4paI4paI4pWRICAgICDilojilojilZEgICAgIOKWiOKWiOKWiOKWiOKWiOKVlOKVnSDilojilojilojilojilojilojilojilZfilojilojilZTilojilojilZcg4paI4paI4pWR4paI4paI4paI4paI4paI4paI4paI4pWR4paI4paI4paI4paI4paI4pWU4pWdIOKWiOKWiOKWiOKWiOKWiOKVlyAgCiDilojilojilZTilZDilZDilojilojilZfilojilojilZEgICAgIOKWiOKWiOKVkSAgICAg4paI4paI4pWU4pWQ4paI4pWXIOKVmuKVkOKVkOKVkOKVkOKWiOKWiOKVl+KWiOKWiOKVkeKVmuKWiOKWiOKVl+KWiOKWiOKVkeKWiOKWiOKVlOKVkOKVkOKWiOKWiOKVl+KWiOKWiOKVlOKVkOKWiOKVlyDilojilojilZTilZDilZDilZ0gIAog4paI4paI4paI4paI4paI4paI4pWU4pWd4paI4paI4paI4paI4paI4paI4paI4pWX4pWa4paI4paI4paI4paI4paI4paI4pWX4paI4paI4pWRICDilojilojilZHilojilojilojilojilojilojilojilZHilojilojilZEg4pWa4paI4paI4paI4paI4pWR4paI4paI4pWRICDilojilojilZHilojilojilZEgIOKWiOKWiOKVkeKWiOKWiOKWiOKWiOKWiOKWiOKWiOKVlwog4pWa4pWQ4pWQ4pWQ4pWQ4pWQ4pWdIOKVmuKVkOKVkOKVkOKVkOKVkOKVkOKVnSDilZrilZDilZDilZDilZDilZDilZ3ilZrilZ0gIOKVmuKVneKVmuKVkOKVkOKVkOKVkOKVkOKVkOKVneKVmuKVnSAg4pWa4pWQ4pWQ4pWQ4pWd4pWa4pWdICDilZrilZ3ilZrilZ0gIOKVmuKVneKVmuKVkOKVkOKVkOKVkOKVkOKVkOKVnQ=="
    $art = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b64))
    Write-Host ""
    $art -split "`n" | ForEach-Object { Write-Host "  $_" -ForegroundColor Yellow }
    Write-Host ""
    $sep = "=" * 78
    Write-Host "  $sep" -ForegroundColor Yellow
    Write-Host "   NIST SP 800-88r2  |  Secure Disk Wipe Tool  |  v2.0" -ForegroundColor Yellow
    Write-Host "   by Jeysson Rostran  |  BLCKSNAKE Security Tools  |  blcksnake.com" -ForegroundColor DarkYellow
    Write-Host "  $sep" -ForegroundColor Yellow
    Write-Host ""
}

function Write-SectionHeader([string]$title) {
    $pad = "-" * [Math]::Max(0, 60 - $title.Length)
    Write-Host ""
    Write-Host "  -- $title $pad" -ForegroundColor Yellow
}

function Write-Step([string]$msg)  { Write-Host "  [*] $msg" -ForegroundColor Cyan }
function Write-Ok([string]$msg)    { Write-Host "  [+] $msg" -ForegroundColor Green }
function Write-Warn([string]$msg)  { Write-Host "  [!] $msg" -ForegroundColor Yellow }
function Write-Err([string]$msg)   { Write-Host "  [X] $msg" -ForegroundColor Red }

function Read-YesNo([string]$question, [bool]$defaultYes = $false) {  # Read is an approved verb
    $choices = if ($defaultYes) { "[Y/n]" } else { "[y/N]" }
    Write-Host "  $question $choices " -NoNewline -ForegroundColor Cyan
    $resp = (Read-Host).Trim().ToLower()
    if ($resp -eq '') { return $defaultYes }
    return ($resp -eq 'y' -or $resp -eq 'yes')
}

function Show-Progress([double]$pct, [double]$mbps, [long]$elapsedSec) {
    $bar    = [int]($pct / 2)
    $filled = '#' * $bar
    $empty  = '-' * (50 - $bar)
    $eta    = if ($pct -gt 0) { [int]($elapsedSec / $pct * (100 - $pct)) } else { 0 }
    $etaStr = if ($eta -gt 3600) {
        "{0:00}h{1:00}m" -f [int]($eta / 3600), [int](($eta % 3600) / 60)
    } elseif ($eta -gt 60) {
        "{0:00}m{1:00}s" -f [int]($eta / 60), ($eta % 60)
    } else { "${eta}s" }
    $line = "`r  [{0}{1}] {2,5:F1}%  {3,6:F1} MB/s  ETA {4,8}" -f `
        $filled, $empty, $pct, $mbps, $etaStr
    Write-Host $line -NoNewline -ForegroundColor White
}

# ---- Drive enumeration (pure P/Invoke - no WMI, safe in WinPE) --------------
function Get-PhysicalDrives {
    $drives = @()
    # Probe PhysicalDrive0..15; stop after 3 consecutive misses
    $miss = 0
    for ($i = 0; $i -le 15; $i++) {
        try {
            $h    = [DiskOps]::OpenDisk($i)
            $size = [DiskOps]::GetDiskSize($h)
            $h.Dispose()
            if ($size -le 0) { $miss++; continue }
            $miss = 0
        } catch { $miss++; if ($miss -ge 3) { break }; continue }

        $info = [DiskOps]::QueryDeviceProperty($i)

        $busName = switch ($info.BusType) {
            3  { "ATA/SATA" }
            6  { "SCSI" }
            7  { "USB" }
            9  { "NVMe" }
            11 { "SAS" }
            17 { "SAS" }
            default { "Bus$($info.BusType)" }
        }

        # Detect SSD vs HDD from ATA IDENTIFY DEVICE Word 217 (byte 434)
        # 0x0001 = SSD, 0x0002 = HDD/rotational
        $mediaType = if ($info.BusType -eq 9) { "NVMe" } else { "HDD" }
        try {
            $hId = [DiskOps]::OpenDisk($i)
            $id  = [DiskOps]::AtaIdentify($hId)
            $hId.Dispose()
            $w217 = [BitConverter]::ToUInt16($id, 434)
            if ($w217 -eq 1) { $mediaType = "SSD" }
        } catch {}

        # Clean strings from STORAGE_DEVICE_DESCRIPTOR
        # Virtual/Hyper-V disks return certificate DN strings in the serial field
        # (e.g. "UUS10UWashington10URedmond10UMicrosoft Corporation...") -- detect and discard
        $cleanStr = {
            param($s)
            $out = ($s -replace '[^\x20-\x7E]','').Trim()  # strip non-printable
            $out = ($out -split '\s+')[0].Trim()            # take first token only
            if ($out -match '(Microsoft|Washington|Redmond|Corporation|=|CN=|OU=|DC=)') {
                $out = ""  # certificate DN - not a real serial
            }
            if ($out.Length -gt 40) { $out = $out.Substring(0, 40) }  # cap length
            return $out
        }
        $model    = & $cleanStr $info.Model;  if (-not $model)  { $model  = "[Virtual/Unknown]" }
        $serial   = & $cleanStr $info.Serial; if (-not $serial) { $serial = "N/A" }
        $vendor   = & $cleanStr $info.VendorId

        $drives += [PSCustomObject]@{
            Index     = $i
            Model     = $model
            Serial    = $serial
            Vendor    = $vendor
            SizeGB    = [Math]::Round($size / 1GB, 1)
            SizeBytes = $size
            Bus       = $busName
            MediaType = $mediaType
            BusTypeId = $info.BusType
        }
    }
    return $drives
}

# ---- ATA capabilities from IDENTIFY DEVICE ----------------------------------
function Get-AtaCapabilities([int]$index) {
    $cap = [PSCustomObject]@{
        SecuritySupported        = $false
        SecurityEnabled          = $false
        SecurityFrozen           = $false
        EnhancedEraseSupported   = $false
        SanitizeSupported        = $false
        CryptoScrambleSupported  = $false
        BlockEraseSupported      = $false
        EraseTimeMinutes         = 0
        EnhancedEraseTimeMinutes = 0
    }
    try {
        $h = [DiskOps]::OpenDisk($index)
        try {
            $id = [DiskOps]::AtaIdentify($h)

            # Word 128 (byte offset 256) = Security Status
            $secStatus = [BitConverter]::ToUInt16($id, 256)
            $cap.SecuritySupported       = ($secStatus -band 0x0001) -ne 0
            $cap.SecurityEnabled         = ($secStatus -band 0x0002) -ne 0
            $cap.SecurityFrozen          = ($secStatus -band 0x0008) -ne 0
            $cap.EnhancedEraseSupported  = ($secStatus -band 0x0020) -ne 0

            # Word 59 (byte offset 118): bit12=SANITIZE, bit13=CRYPTO_SCRAMBLE, bit14=BLOCK_ERASE
            $w59 = [BitConverter]::ToUInt16($id, 118)
            $cap.SanitizeSupported       = ($w59 -band 0x1000) -ne 0
            $cap.CryptoScrambleSupported = ($w59 -band 0x2000) -ne 0
            $cap.BlockEraseSupported     = ($w59 -band 0x4000) -ne 0

            # Words 89/90 (byte offsets 178/180) = erase times (bits 14:8 * 2 minutes)
            $w89 = [BitConverter]::ToUInt16($id, 178)
            $w90 = [BitConverter]::ToUInt16($id, 180)
            if (($w89 -band 0x8000) -ne 0) {
                $cap.EraseTimeMinutes         = (($w89 -band 0x7F00) -shr 8) * 2
                $cap.EnhancedEraseTimeMinutes = (($w90 -band 0x7F00) -shr 8) * 2
            }
        } finally { $h.Dispose() }
    } catch {
        # ATA IDENTIFY not available for USB/NVMe -- silently continue with defaults
    }
    return $cap
}

# ---- Wipe methods ------------------------------------------------------------

function Invoke-ClearOverwrite([PSCustomObject]$drive, [int]$passes = 1) {
    $passLabel = "$passes-pass overwrite"
    Write-SectionHeader "CLEAR - Overwrite with zeros ($passLabel)"
    Write-Warn "This will PERMANENTLY destroy all data on PhysicalDrive$($drive.Index)!"
    Write-Host "  Drive : $($drive.Model)  [$($drive.SizeGB) GB]" -ForegroundColor White
    Write-Host "  Method: Overwrite all addressable sectors with 0x00 ($passes pass)" -ForegroundColor White
    Write-Host "  NIST  : SP 800-88r2 Section 3.1.1 - Clear" -ForegroundColor White
    Write-Host ""
    if (-not (Read-YesNo "Confirm DESTROY ALL DATA on this drive?")) { return $null }

    $startTime   = Get-Date
    $script:_sw  = [System.Diagnostics.Stopwatch]::StartNew()

    $progress = [Action[double,double]]{
        param($pct, $mbps)
        Show-Progress $pct $mbps ([long]$script:_sw.Elapsed.TotalSeconds)
    }

    Write-Host ""
    try {
        [DiskOps]::OverwriteWithZeros($drive.Index, $drive.SizeBytes, $progress, $passes)
        Write-Host ""
        Write-Ok "Overwrite complete."
    } catch {
        Write-Host ""
        Write-Err "Overwrite failed: $_"
        return $null
    }

    # ---- Verification (NIST 800-88r2 s4.5.1 sampling) -------------------------
    Write-Step "Verifying wipe by sampling 256 random sectors..."
    $verifyFailed = 0
    $verifyNote   = ""
    try {
        $vProgress = [Action[double]]{ param($p)
            Write-Host ("`r  Verifying... {0,5:F1}%" -f $p) -NoNewline
        }
        $verifyFailed = [DiskOps]::VerifyZeros($drive.Index, $drive.SizeBytes, 256, $vProgress)
        Write-Host ""
        if ($verifyFailed -eq 0) {
            Write-Ok "Verification PASSED - all 256 sampled sectors contain zeros."
            $verifyNote = "Verified: 256 random sectors sampled, all zeros (NIST SP 800-88r2 Section 4.5.1)"
        } else {
            Write-Err "Verification FAILED - $verifyFailed of 256 sampled sectors were non-zero."
            $verifyNote = "VERIFICATION FAILED: $verifyFailed of 256 sampled sectors were non-zero"
        }
    } catch {
        Write-Warn "Verification skipped: $_"
        $verifyNote = "Verification skipped: $_"
    }

    return [PSCustomObject]@{
        Drive     = $drive
        Method    = "Clear"
        SubMethod = "Overwrite 0x00 x $passes pass"
        NISTRef   = "SP 800-88r2 Section 3.1.1 - Clear"
        StartTime = $startTime
        EndTime   = Get-Date
        Duration  = $script:_sw.Elapsed.ToString("hh\:mm\:ss")
        Success   = ($verifyFailed -eq 0)
        Notes     = $verifyNote
        Operator  = $env:USERNAME
    }
}

function Invoke-PurgeAtaSecureErase([PSCustomObject]$drive, [PSCustomObject]$cap) {
    $useEnhanced = $cap.EnhancedEraseSupported
    $label       = if ($useEnhanced) { "SECURITY ERASE ENHANCED" } else { "SECURITY ERASE UNIT" }
    $etaMin      = if ($useEnhanced -and $cap.EnhancedEraseTimeMinutes -gt 0) {
                       $cap.EnhancedEraseTimeMinutes
                   } elseif ($cap.EraseTimeMinutes -gt 0) {
                       $cap.EraseTimeMinutes
                   } else { "unknown" }

    Write-SectionHeader "PURGE - ATA $label"
    Write-Warn "This will PERMANENTLY destroy all data on PhysicalDrive$($drive.Index)!"
    Write-Host "  Drive : $($drive.Model)  [$($drive.SizeGB) GB]" -ForegroundColor White
    Write-Host "  Method: ATA $label" -ForegroundColor White
    Write-Host "  Time  : ~$etaMin minutes (drive-controlled)" -ForegroundColor White
    Write-Host "  NIST  : SP 800-88r2 Section 3.1.2 - Purge" -ForegroundColor White

    if ($cap.SecurityFrozen) {
        Write-Err "Drive security is FROZEN - ATA Secure Erase is blocked by the BIOS."
        Write-Warn "Hot-unplug/replug the SATA cable, then retry. Or choose Overwrite instead."
        return $null
    }
    Write-Host ""
    if (-not (Read-YesNo "Confirm PURGE this drive via ATA Secure Erase?")) { return $null }

    $startTime = Get-Date
    $ok = $false
    try {
        Write-Step "Opening drive handle..."
        $h = [DiskOps]::OpenDisk($drive.Index, $true)
        try {
            Write-Step "Setting NULL security password..."
            [DiskOps]::AtaSecuritySetPassword($h)
            Write-Step "Issuing SECURITY ERASE PREPARE..."
            [DiskOps]::AtaSecurityErasePrepare($h)
            Write-Step "Issuing $label (timeout 6 hours -- do NOT power off)..."
            Write-Warn "Drive is erasing. Please wait..."
            [DiskOps]::AtaSecurityEraseUnit($h, $useEnhanced, 21600)
            $ok = $true
            Write-Ok "ATA Secure Erase completed."
        } finally { $h.Dispose() }
    } catch {
        Write-Err "ATA Secure Erase failed: $_"
        return $null
    }

    $noteText = if ($useEnhanced) {
        "Enhanced erase - all user data areas sanitized including overprovisioning"
    } else {
        "Normal erase"
    }

    return [PSCustomObject]@{
        Drive     = $drive
        Method    = "Purge"
        SubMethod = "ATA $label"
        NISTRef   = "SP 800-88r2 Section 3.1.2 - Purge"
        StartTime = $startTime
        EndTime   = Get-Date
        Duration  = (New-TimeSpan $startTime (Get-Date)).ToString("hh\:mm\:ss")
        Success   = $ok
        Notes     = $noteText
        Operator  = $env:USERNAME
    }
}

function Invoke-PurgeAtaSanitize([PSCustomObject]$drive, [PSCustomObject]$cap) {
    $useCrypto = $cap.CryptoScrambleSupported
    $label     = if ($useCrypto) { "CRYPTO SCRAMBLE EXT" } else { "BLOCK ERASE EXT" }

    Write-SectionHeader "PURGE - ATA SANITIZE $label"
    Write-Warn "This will PERMANENTLY destroy all data on PhysicalDrive$($drive.Index)!"
    Write-Host "  Drive : $($drive.Model)  [$($drive.SizeGB) GB]" -ForegroundColor White
    Write-Host "  Method: ATA SANITIZE $label" -ForegroundColor White
    Write-Host "  NIST  : SP 800-88r2 Section 3.1.2 - Purge (Sanitize)" -ForegroundColor White
    Write-Host ""
    if (-not (Read-YesNo "Confirm PURGE this drive via ATA Sanitize?")) { return $null }

    $startTime = Get-Date
    $ok = $false
    try {
        $h = [DiskOps]::OpenDisk($drive.Index, $true)
        try {
            Write-Step "Issuing SANITIZE $label (timeout 6 hours -- do NOT power off)..."
            Write-Warn "Drive is sanitizing. Please wait..."
            [DiskOps]::AtaSanitize($h, $useCrypto, 21600)
            $ok = $true
            Write-Ok "ATA Sanitize completed."
        } finally { $h.Dispose() }
    } catch {
        Write-Err "ATA Sanitize failed: $_"
        return $null
    }

    $noteText = if ($useCrypto) {
        "Cryptographic scramble - internal encryption key discarded, all data unreadable"
    } else {
        "Block erase - all NAND cells erased including overprovisioning areas"
    }

    return [PSCustomObject]@{
        Drive     = $drive
        Method    = "Purge"
        SubMethod = "ATA SANITIZE $label"
        NISTRef   = "SP 800-88r2 Section 3.1.2 - Purge"
        StartTime = $startTime
        EndTime   = Get-Date
        Duration  = (New-TimeSpan $startTime (Get-Date)).ToString("hh\:mm\:ss")
        Success   = $ok
        Notes     = $noteText
        Operator  = $env:USERNAME
    }
}

function Invoke-PurgeNvmeSanitize([PSCustomObject]$drive) {
    Write-SectionHeader "PURGE - NVMe Sanitize (Crypto Erase)"
    Write-Warn "This will PERMANENTLY destroy all data on PhysicalDrive$($drive.Index)!"
    Write-Host "  Drive : $($drive.Model)  [$($drive.SizeGB) GB]" -ForegroundColor White
    Write-Host "  Method: NVMe Sanitize - Crypto Erase (SANACT=1)" -ForegroundColor White
    Write-Host "  NIST  : SP 800-88r2 Section 3.1.2 - Purge" -ForegroundColor White
    Write-Host ""
    if (-not (Read-YesNo "Confirm PURGE this NVMe drive?")) { return $null }

    $startTime = Get-Date
    $ok = $false
    try {
        $h = [DiskOps]::OpenDisk($drive.Index, $true)
        try {
            Write-Step "Issuing NVMe Sanitize - Crypto Erase (timeout 6 hours)..."
            Write-Warn "Drive is sanitizing. Please wait..."
            [DiskOps]::NvmeSanitize($h, 1, 21600)  # 1 = Crypto Erase
            $ok = $true
            Write-Ok "NVMe Sanitize completed."
        } finally { $h.Dispose() }
    } catch {
        Write-Err "NVMe Crypto Erase failed: $_"
        Write-Warn "Falling back to overwrite method..."
        return Invoke-ClearOverwrite $drive
    }

    return [PSCustomObject]@{
        Drive     = $drive
        Method    = "Purge"
        SubMethod = "NVMe Sanitize - Crypto Erase"
        NISTRef   = "SP 800-88r2 Section 3.1.2 - Purge"
        StartTime = $startTime
        EndTime   = Get-Date
        Duration  = (New-TimeSpan $startTime (Get-Date)).ToString("hh\:mm\:ss")
        Success   = $ok
        Notes     = "NVMe Sanitize action 1 (Crypto Erase) - encryption key discarded, all namespaces"
        Operator  = $env:USERNAME
    }
}

# ---- Compliance report generation -------------------------------------------
function New-ComplianceReport([PSCustomObject[]]$results) {
    $ts      = Get-Date -Format "yyyyMMdd_HHmmss"
    $outDir  = if (Test-Path "X:\") { "X:\WipeReports" } else { "$env:TEMP\WipeReports" }
    if (-not (Test-Path $outDir)) { New-Item -ItemType Directory $outDir | Out-Null }
    $txtFile  = Join-Path $outDir "WipeReport_$ts.txt"
    $htmlFile = Join-Path $outDir "WipeReport_$ts.html"
    $hostname = $env:COMPUTERNAME
    $now      = Get-Date -Format "yyyy-MM-dd HH:mm:ss UTC"

    # ---- Plain text report (Appendix C template) ----------------------------
    $lines = @(
        "=" * 68
        "  MEDIA SANITIZATION COMPLIANCE RECORD"
        "  NIST SP 800-88 Revision 2 -- Appendix C Template"
        "=" * 68
        ""
        "Organization  : <FILL IN>"
        "Prepared by   : $($env:USERNAME)"
        "Hostname      : $hostname"
        "Report date   : $now"
        ""
        "-" * 68
        "  SANITIZATION RECORDS"
        "-" * 68
    )

    foreach ($r in $results) {
        $lines += @(
            ""
            "  Drive Index  : PhysicalDrive$($r.Drive.Index)"
            "  Make / Model : $($r.Drive.Vendor) $($r.Drive.Model)"
            "  Serial No.   : $($r.Drive.Serial)"
            "  Capacity     : $($r.Drive.SizeGB) GB"
            "  Interface    : $($r.Drive.Bus)"
            "  Media Type   : $($r.Drive.MediaType)"
            ""
            "  NIST Method  : $($r.Method)"
            "  Sub-method   : $($r.SubMethod)"
            "  Reference    : $($r.NISTRef)"
            "  Started      : $($r.StartTime)"
            "  Finished     : $($r.EndTime)"
            "  Duration     : $($r.Duration)"
            "  Result       : $(if ($r.Success) { 'SUCCESS' } else { 'FAILED' })"
            "  Notes        : $($r.Notes)"
            ""
            "  Operator sig : ______________________________  Date: ____________"
        )
    }

    $lines += @(
        ""
        "-" * 68
        "  DISPOSITION"
        "-" * 68
        ""
        "  Sanitization verified by: ______________________________"
        "  Title / Role            : ______________________________"
        "  Date                    : ______________________________"
        "  Signature               : ______________________________"
        ""
        "  Media disposition after sanitization:"
        "    [ ] Reuse within organization"
        "    [ ] Transfer / donation"
        "    [ ] Recycling / destruction"
        "    [ ] Other: _______________________________"
        ""
        "=" * 68
        "  Generated by NIST 800-88r2 SecureWipe Tool v2.0"
        "=" * 68
    )
    $lines | Out-File -FilePath $txtFile -Encoding UTF8

    # ---- HTML report --------------------------------------------------------
    $rows = ($results | ForEach-Object {
        $bg    = if ($_.Success) { "rgba(0,180,60,0.18)" } else { "rgba(220,30,30,0.22)" }
        $label = if ($_.Success) { "SUCCESS" } else { "FAILED" }
        "<tr style='background:$bg'>" +
        "<td>PhysicalDrive$($_.Drive.Index)</td>" +
        "<td>$($_.Drive.Vendor) $($_.Drive.Model)</td>" +
        "<td>$($_.Drive.Serial)</td>" +
        "<td>$($_.Drive.SizeGB) GB</td>" +
        "<td>$($_.Drive.Bus) / $($_.Drive.MediaType)</td>" +
        "<td>$($_.Method)</td>" +
        "<td>$($_.SubMethod)</td>" +
        "<td>$($_.NISTRef)</td>" +
        "<td>$($_.StartTime)</td>" +
        "<td>$($_.Duration)</td>" +
        "<td><strong>$label</strong></td>" +
        "<td>$($_.Notes)</td>" +
        "</tr>"
    }) -join "`n"

    # BLCKSNAKE brand: #FDB913 yellow / #001E3A navy / #001628 dark / #E6E7E8 grey
    $css = @(
        "* { box-sizing:border-box; margin:0; padding:0; }"
        "body { font-family:Montserrat,Arial,sans-serif; font-size:13px; background:#001E3A; color:#E6E7E8; }"
        ".header { background:#000; border-bottom:3px solid #FDB913; padding:18px 28px; display:flex; align-items:center; gap:18px; }"
        ".logo { width:54px; height:54px; background:#FDB913; border-radius:50%; display:flex; align-items:center; justify-content:center; font-size:10px; font-weight:900; color:#000; text-align:center; line-height:1.2; flex-shrink:0; }"
        ".brand-name { color:#FDB913; font-size:22px; font-weight:900; letter-spacing:3px; }"
        ".brand-sub  { color:#E6E7E8; font-size:11px; letter-spacing:1px; margin-top:3px; opacity:.8; }"
        ".content { padding:22px 28px; }"
        "h1 { color:#FDB913; font-size:17px; font-weight:700; margin-bottom:3px; }"
        "h2 { color:#FDB913; font-size:13px; font-weight:600; margin:18px 0 7px; padding-bottom:4px; border-bottom:1px solid #FDB913; }"
        ".ref { font-size:11px; opacity:.6; margin-bottom:14px; }"
        ".meta { background:#001628; border:1px solid #FDB913; border-radius:5px; padding:12px 16px; margin-bottom:18px; line-height:2; }"
        ".meta strong { color:#FDB913; }"
        "table { border-collapse:collapse; width:100%; font-size:12px; margin-top:6px; }"
        "th { background:#FDB913; color:#000; padding:9px 10px; text-align:left; font-weight:700; }"
        "td { padding:8px 10px; border-bottom:1px solid #001628; vertical-align:top; }"
        "tr:nth-child(even) td { background:rgba(0,22,40,.5); }"
        ".pass { color:#00C853; font-weight:700; } .fail { color:#FF1744; font-weight:700; }"
        ".signoff { background:#001628; border-radius:5px; padding:14px 16px; }"
        ".sf-row { display:flex; gap:20px; margin-bottom:12px; }"
        ".sf-field { flex:1; }"
        ".sf-label { font-size:10px; color:#FDB913; margin-bottom:2px; }"
        ".sf-line { border-bottom:1px solid #FDB913; padding-bottom:5px; min-height:22px; }"
        "ul { list-style:none; padding-left:8px; }"
        "li { padding:3px 0; } li:before { content:'[ ] '; color:#FDB913; }"
        ".footer { margin-top:24px; padding-top:12px; border-top:1px solid #FDB913; font-size:11px; color:#FDB913; text-align:center; opacity:.8; }"
    ) -join " "

    $html  = "<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'>`n"
    $html += "<title>BLCKSNAKE SecureWipe Report $ts</title>`n"
    $html += "<style>$css</style></head><body>`n"
    $html += "<div class='header'>`n"
    $html += "  <img src='data:image/png;base64,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' width='60' height='60' style='border-radius:50%;display:block;' alt='BLCKSNAKE Logo'/>
"
    $html += "  <div><div class='brand-name'>BLCKSNAKE</div>"
    $html += "<div class='brand-sub'>SECURITY TOOLS &nbsp;|&nbsp; SecureWipe v2.0 &nbsp;|&nbsp; NIST SP 800-88r2</div></div>`n"
    $html += "</div><div class='content'>`n"
    $html += "<h1>Certificate of Sanitization</h1>`n"
    $html += "<p class='ref'>NIST SP 800-88 Revision 2 (September 2025) -- Appendix C / Section 4.6 &nbsp;|&nbsp; DOI: 10.6028/NIST.SP.800-88r2</p>`n"
    $html += "<div class='meta'><strong>Organization:</strong> [FILL IN] &nbsp; <strong>Operator:</strong> $($env:USERNAME) &nbsp; <strong>Host:</strong> $hostname &nbsp; <strong>Date:</strong> $now</div>`n"
    $html += "<h2>Sanitization Records</h2><table>`n"
    $html += "<tr><th>Drive</th><th>Make/Model</th><th>Serial</th><th>Size</th><th>Interface</th>"
    $html += "<th>Method</th><th>Sub-method</th><th>NIST Ref</th><th>Start</th><th>Duration</th>"
    $html += "<th>Result</th><th>Verification / Notes</th></tr>`n"
    $html += "$rows`n</table>`n"
    $html += "<h2>Verification and Validation (Section 4.5)</h2>`n"
    $html += "<div class='signoff'><div class='sf-row'>`n"
    $html += "<div class='sf-field'><div class='sf-label'>VERIFIED BY</div><div class='sf-line'>&nbsp;</div></div>`n"
    $html += "<div class='sf-field'><div class='sf-label'>TITLE / ROLE</div><div class='sf-line'>&nbsp;</div></div>`n"
    $html += "<div class='sf-field'><div class='sf-label'>DATE</div><div class='sf-line'>&nbsp;</div></div>`n"
    $html += "<div class='sf-field'><div class='sf-label'>SIGNATURE</div><div class='sf-line'>&nbsp;</div></div>`n"
    $html += "</div></div>`n"
    $html += "<h2>Media Disposition After Sanitization</h2><ul>`n"
    $html += "<li>Reuse within organization</li><li>Transfer / donation</li>`n"
    $html += "<li>Recycling / physical destruction</li><li>Other: _______________</li></ul>`n"
    $html += "<div class='footer'>BLCKSNAKE SecureWipe v2.0 &nbsp;|&nbsp; Jeysson Rostran &nbsp;|&nbsp; NIST SP 800-88r2 Compliant &nbsp;|&nbsp; blcksnake.com</div>`n"
    $html += "</div></body></html>"

    $html | Out-File -FilePath $htmlFile -Encoding UTF8

    return [PSCustomObject]@{ TxtPath = $txtFile; HtmlPath = $htmlFile }
}

# ---- Drive selection menu ---------------------------------------------------
function Show-DriveMenu([PSCustomObject[]]$drives) {
    Write-SectionHeader "Detected Physical Drives"
    Write-Host ("  {0,-4} {1,-35} {2,-18} {3,8}  {4,-8}  {5}" -f `
        "Idx", "Model", "Serial", "Size(GB)", "Bus", "Type") -ForegroundColor Cyan
    Write-Host ("  " + "-" * 78) -ForegroundColor DarkGray
    foreach ($d in $drives) {
        $serial = if ($d.Serial.Length -gt 18) { $d.Serial.Substring(0,15) + "..." } else { $d.Serial }
        $model  = if ($d.Model.Length  -gt 35) { $d.Model.Substring(0,32)  + "..." } else { $d.Model  }
        Write-Host ("  {0,-4} {1,-35} {2,-18} {3,8}  {4,-8}  {5}" -f `
            $d.Index, $model, $serial, $d.SizeGB, $d.Bus, $d.MediaType)
    }
    Write-Host ""
    Write-Host "  Enter drive index (e.g. 1) or 'q' to quit: " -NoNewline -ForegroundColor Cyan
    return (Read-Host).Trim()
}

# ---- Wipe method menu -------------------------------------------------------
function Show-MethodMenu([PSCustomObject]$drive, [PSCustomObject]$cap) {
    Write-SectionHeader "Select Sanitization Method"
    Write-Host "  Drive: $($drive.Model)  [$($drive.SizeGB) GB]  ($($drive.Bus) / $($drive.MediaType))" -ForegroundColor White
    Write-Host ""

    $options = @()

    if ($drive.MediaType -eq "NVMe") {
        Write-Host "  [1] PURGE  - NVMe Sanitize Crypto Erase        [NIST SP 800-88r2 Sec.3.1.2]" -ForegroundColor Green
        Write-Host "  [2] CLEAR  - Overwrite with zeros (1 pass)     [NIST SP 800-88r2 Sec.3.1.2]" -ForegroundColor Yellow
        $options = @("NvmePurge", "Clear1Pass")
    } elseif ($drive.MediaType -eq "SSD") {
        if ($cap.SanitizeSupported) {
            Write-Host "  [1] PURGE  - ATA Sanitize (Crypto/Block Erase) [NIST SP 800-88r2 Sec.3.1.2]" -ForegroundColor Green
        } else {
            Write-Host "  [1] PURGE  - ATA Sanitize  [NOT SUPPORTED by this drive]" -ForegroundColor DarkGray
        }
        if ($cap.SecuritySupported -and -not $cap.SecurityFrozen) {
            Write-Host "  [2] PURGE  - ATA Security Erase Enhanced       [NIST SP 800-88r2 Sec.3.1.2]" -ForegroundColor Green
        } else {
            Write-Host "  [2] PURGE  - ATA Security Erase  [FROZEN or unsupported]" -ForegroundColor DarkGray
        }
        Write-Host "  [3] CLEAR  - Overwrite with zeros (1 pass)     [NIST SP 800-88r2 Sec.3.1.2]" -ForegroundColor Yellow
        $options = @("SsdSanitize", "SsdSecureErase", "Clear1Pass")
    } else {
        # HDD
        if ($cap.SecuritySupported -and -not $cap.SecurityFrozen) {
            $enh = if ($cap.EnhancedEraseSupported) { "Enhanced" } else { "Normal" }
            Write-Host "  [1] PURGE  - ATA Security Erase ($enh)        [NIST SP 800-88r2 Sec.3.1.1]" -ForegroundColor Green
        } else {
            Write-Host "  [1] PURGE  - ATA Security Erase  [FROZEN or unsupported]" -ForegroundColor DarkGray
        }
        Write-Host "  [2] CLEAR  - Overwrite with zeros (1 pass)     [NIST SP 800-88r2 Sec.3.1.1]" -ForegroundColor Yellow
        Write-Host "  [3] CLEAR+ - Overwrite with zeros (3 passes)   [NIST SP 800-88r2 Sec.3.1.1]" -ForegroundColor Yellow
        $options = @("HddSecureErase", "Clear1Pass", "Clear3Pass")
    }
    Write-Host "  [0] Back"
    Write-Host ""
    Write-Host "  Choice: " -NoNewline -ForegroundColor Cyan
    $choice = (Read-Host).Trim()
    if ($choice -eq '0') { return $null }
    $idx = [int]$choice - 1
    if ($idx -lt 0 -or $idx -ge $options.Count) { return $null }
    return $options[$idx]
}

# ---- Main loop --------------------------------------------------------------
function Main {
    Write-Banner
    Write-Host "  WARNING: This tool PERMANENTLY destroys data." -ForegroundColor Red
    Write-Host "  Confirm your drive selection carefully. There is NO undo." -ForegroundColor Red
    Write-Host ""

    $completedWipes = @()

    while ($true) {
        Write-Banner
        Write-Step "Enumerating physical drives..."
        $drives = @(Get-PhysicalDrives)
        if ($drives.Count -eq 0) {
            Write-Err "No physical drives found."
            break
        }

        $sel = Show-DriveMenu $drives
        if ($sel -eq 'q' -or $sel -eq 'Q') { break }

        $driveIdx = try { [int]$sel } catch { -1 }
        if ($driveIdx -lt 0) { Write-Warn "Invalid input."; Start-Sleep 1; continue }

        $drive = $drives | Where-Object { $_.Index -eq $driveIdx } | Select-Object -First 1
        if (-not $drive) { Write-Warn "Drive index $driveIdx not found."; Start-Sleep 1; continue }

        Write-Step "Querying ATA capabilities for PhysicalDrive$($drive.Index)..."
        $cap = Get-AtaCapabilities $drive.Index

        $method = Show-MethodMenu $drive $cap
        if (-not $method) { continue }

        $result = $null
        switch ($method) {
            "NvmePurge"     { $result = Invoke-PurgeNvmeSanitize   $drive }
            "SsdSanitize"   { $result = Invoke-PurgeAtaSanitize     $drive $cap }
            "SsdSecureErase"{ $result = Invoke-PurgeAtaSecureErase  $drive $cap }
            "HddSecureErase"{ $result = Invoke-PurgeAtaSecureErase  $drive $cap }
            "Clear1Pass"    { $result = Invoke-ClearOverwrite        $drive 1 }
            "Clear3Pass"    { $result = Invoke-ClearOverwrite        $drive 3 }
        }

        if ($result) {
            $completedWipes += $result
            Write-SectionHeader "Wipe Complete"
            $color = if ($result.Success) { "Green" } else { "Red" }
            $status = if ($result.Success) { "SUCCESS" } else { "FAILED" }
            Write-Host "  Result  : $status" -ForegroundColor $color
            Write-Host "  Method  : $($result.SubMethod)"
            Write-Host "  Duration: $($result.Duration)"
        }

        $again = Read-YesNo "Wipe another drive?" $false
        if (-not $again) { break }
    }

    if ($completedWipes.Count -gt 0) {
        Write-SectionHeader "Generating Compliance Report"
        try {
            $rpt = New-ComplianceReport $completedWipes
            Write-Ok "TXT  report: $($rpt.TxtPath)"
            Write-Ok "HTML report: $($rpt.HtmlPath)"

            # Display TXT report in console
            Write-Host ""
            Write-Host ("=" * 68) -ForegroundColor Cyan
            Get-Content $rpt.TxtPath | ForEach-Object { Write-Host "  $_" }
            Write-Host ("=" * 68) -ForegroundColor Cyan

            # Try to open HTML with mshta.exe (requires WinPE-HTA component)
            $mshta = "X:\Windows\System32\mshta.exe"
            if (Test-Path $mshta) {
                Write-Host ""
                Write-Step "Opening HTML report in viewer..."
                Start-Process $mshta -ArgumentList $rpt.HtmlPath -Wait
            } else {
                Write-Warn "No HTML viewer in WinPE -- copy reports off before rebooting."
            }

            Write-Host ""
            Write-Warn "IMPORTANT: Copy reports to a USB drive or network share before rebooting!"
            Write-Host "  Reports are on the RAM disk (X:) and will be LOST on reboot." -ForegroundColor Yellow
            Write-Host ""
            Write-Host "  To copy to a USB drive (e.g. D:):" -ForegroundColor White
            Write-Host "  xcopy X:\WipeReports D:\WipeReports /E /I /Y" -ForegroundColor White
        } catch {
            Write-Err "Report generation failed: $_"
        }
    }

    Write-Host ""
    Write-Host "  Session complete. Press Enter to exit." -ForegroundColor Cyan
    Read-Host | Out-Null
}

try {
    Main
} catch {
    $errLog = "X:\WipeTool\error.log"
    $msg    = "FATAL ERROR: $_`n$($_.ScriptStackTrace)"
    Write-Host $msg -ForegroundColor Red
    $msg | Out-File $errLog -Encoding UTF8 -ErrorAction SilentlyContinue
    Write-Host ""
    Write-Host "Error saved to $errLog" -ForegroundColor Yellow
    Write-Host "Press Enter to open a recovery shell..." -NoNewline
    Read-Host | Out-Null
    Start-Process cmd.exe
    exit 1
}
