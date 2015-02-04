using System;

namespace Microsoft.Framework.Signing
{
    internal partial class Commands
    {
        public Signer Signer { get; private set; }

        public Commands(Signer signer)
        {
            Signer = signer;
        }
    }
}