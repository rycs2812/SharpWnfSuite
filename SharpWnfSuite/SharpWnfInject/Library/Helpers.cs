﻿using System;
using System.Text;
using SharpWnfInject.Interop;

namespace SharpWnfInject.Library
{
    class Helpers
    {
        private struct WNF_STATE_NAME_DATA
        {
            public ulong Version;
            public ulong NameLifeTime;
            public ulong DataScope;
            public ulong PermanentData;
            public ulong SequenceNumber;
            public ulong OwnerTag;
        }


        private static WNF_STATE_NAME_DATA ConvertFromStateNameToStateData(ulong stateName)
        {
            WNF_STATE_NAME_DATA stateData;
            stateName ^= Win32Const.WNF_STATE_KEY;
            stateData.Version = (stateName & 0xF);
            stateData.NameLifeTime = ((stateName >> 4) & 0x3);
            stateData.DataScope = ((stateName >> 6) & 0xF);
            stateData.PermanentData = ((stateName >> 10) & 0x1);
            stateData.SequenceNumber = ((stateName >> 11) & 0x1FFFFF);
            stateData.OwnerTag = ((stateName >> 32) & 0xFFFFFFFF);

            return stateData;
        }


        public static string GetWnfName(ulong stateName)
        {
            string wnfName;
            WNF_STATE_NAME_DATA data = ConvertFromStateNameToStateData(stateName);
            byte[] tag = BitConverter.GetBytes((uint)data.OwnerTag);
            bool isWellKnown = data.NameLifeTime ==
                (ulong)Win32Const.WNF_STATE_NAME_LIFETIME.WnfWellKnownStateName;

            wnfName = Enum.GetName(typeof(Win32Const.WELL_KNOWN_WNF_NAME), stateName);

            if (string.IsNullOrEmpty(wnfName))
            {
                if (isWellKnown)
                {
                    wnfName = string.Format("{0}.{1} 0x{2}",
                        Encoding.ASCII.GetString(tag).Trim('\0'),
                        data.SequenceNumber.ToString("D3"),
                        stateName.ToString("X8"));
                }
                else
                {
                    wnfName = "N/A";
                }
            }

            return wnfName;
        }


        public static string GetWin32ErrorMessage(int code, bool isNtStatus)
        {
            var message = new StringBuilder();
            var messageSize = 255;
            int converted;
            Win32Const.FormatMessageFlags messageFlag;
            IntPtr pNtdll;
            message.Capacity = messageSize;

            if (isNtStatus)
            {
                converted = Win32Api.RtlNtStatusToDosError(code);

                if (converted == Win32Const.ERROR_MR_MID_NOT_FOUND)
                {
                    pNtdll = Win32Api.LoadLibrary("ntdll.dll");
                    messageFlag = Win32Const.FormatMessageFlags.FORMAT_MESSAGE_FROM_HMODULE |
                        Win32Const.FormatMessageFlags.FORMAT_MESSAGE_FROM_SYSTEM;
                }
                else
                {
                    code = converted;
                    pNtdll = IntPtr.Zero;
                    messageFlag = Win32Const.FormatMessageFlags.FORMAT_MESSAGE_FROM_SYSTEM;
                }
            }
            else
            {
                pNtdll = IntPtr.Zero;
                messageFlag = Win32Const.FormatMessageFlags.FORMAT_MESSAGE_FROM_SYSTEM;
            }

            int ret = Win32Api.FormatMessage(
                messageFlag,
                pNtdll,
                code,
                0,
                message,
                messageSize,
                IntPtr.Zero);

            if (isNtStatus && pNtdll != IntPtr.Zero)
                Win32Api.FreeLibrary(pNtdll);

            if (ret == 0)
            {
                return string.Format("[ERROR] Code 0x{0}", code.ToString("X8"));
            }
            else
            {
                return string.Format(
                    "[ERROR] Code 0x{0} : {1}",
                    code.ToString("X8"),
                    message.ToString().Trim());
            }
        }

    }
}