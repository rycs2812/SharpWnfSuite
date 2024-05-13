﻿using System;

namespace WnfPoolOverflowWin11.Interop
{
    using NTSTATUS = Int32;

    internal class Win32Consts
    {
        public const int STATUS_SUCCESS = 0;
        public static readonly NTSTATUS STATUS_BUFFER_TOO_SMALL = Convert.ToInt32("0xC0000023", 16);

    }
}
