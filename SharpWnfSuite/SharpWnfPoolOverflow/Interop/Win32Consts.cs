using System;

namespace SharpWnfPoolOverflow.Interop
{
    using NTSTATUS = Int32;

    internal class Win32Consts
    {
        public const NTSTATUS STATUS_SUCCESS = 0;
        public static readonly NTSTATUS STATUS_BUFFER_TOO_SMALL = Convert.ToInt32("0xC0000023", 16);
        public static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
    }
}
