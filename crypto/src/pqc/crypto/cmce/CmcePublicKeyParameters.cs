using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Cmce
{
    public class CmcePublicKeyParameters
        : CmceKeyParameters
    {
        internal byte[] publicKey;

        public byte[] GetPublicKey()
        { 
            return Arrays.Clone(publicKey);
        }

        public byte[] GetEncoded()
        {
            return GetPublicKey();
        }

        public CmcePublicKeyParameters(CmceParameters parameters, byte[] publicKey)
            : base(false,  parameters)
        {
            this.publicKey = Arrays.Clone(publicKey);
        }
    }
}
