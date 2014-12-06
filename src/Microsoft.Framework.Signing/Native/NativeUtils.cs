using System;
using System.Runtime.InteropServices;

namespace Microsoft.Framework.Signing.Native
{
    internal static class NativeUtils
    {
        public static void SafeFree(IntPtr ptr)
        {
            if (ptr != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(ptr);
            }
        }

        public static void ThrowIfFailed(bool result)
        {
            if (!result)
            {
                Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());
            }
        }
    }
}