using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace PackageSigning.Native
{
    internal class NativeCms : IDisposable
    {
        private SafeCryptMsgHandle _handle;
        private bool _detached;

        private NativeCms(SafeCryptMsgHandle handle, bool detached)
        {
            _handle = handle;
            _detached = detached;
        }

        public byte[] GetEncryptedDigest()
        {
            // Get the length of the encrypted digest
            uint digestLength = 0;
            if (!NativeMethods.CryptMsgGetParam(
                _handle,
                CMSG_GETPARAM_TYPE.CMSG_ENCRYPTED_DIGEST,
                0,
                IntPtr.Zero,
                ref digestLength))
            {
                Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());
            }

            // Now allocate some memory for it
            IntPtr unmanagedDigestPointer = IntPtr.Zero;
            byte[] data;
            try
            {
                unmanagedDigestPointer = Marshal.AllocHGlobal((int)digestLength);

                // Get the actual digest
                if (!NativeMethods.CryptMsgGetParam(
                    _handle,
                    CMSG_GETPARAM_TYPE.CMSG_ENCRYPTED_DIGEST,
                    0,
                    unmanagedDigestPointer,
                    ref digestLength))
                {
                    Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());
                }

                // Pull it in to managed memory and return it
                data = new byte[digestLength];
                Marshal.Copy(unmanagedDigestPointer, data, 0, data.Length);
            }
            finally
            {
                if (unmanagedDigestPointer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(unmanagedDigestPointer);
                }
            }
            return data;
        }

        public static NativeCms Decode(byte[] input, bool detached)
        {
            var handle = NativeMethods.CryptMsgOpenToDecode(
                CMSG_ENCODING.Any,
                detached ? CMSG_OPENTODECODE_FLAGS.CMSG_DETACHED_FLAG : CMSG_OPENTODECODE_FLAGS.None,
                0u,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero);
            if (handle.IsInvalid)
            {
                Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());
            }

            // Load the data into the message
            if (!NativeMethods.CryptMsgUpdate(handle, input, (uint)input.Length, fFinal: true))
            {
                Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());
            }

            return new NativeCms(handle, detached);
        }

        public void Dispose()
        {
            _handle.Dispose();
        }
    }
}