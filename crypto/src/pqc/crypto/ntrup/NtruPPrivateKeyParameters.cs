using System;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.pqc.crypto.NtruP
{
    public class NtruPPrivateKeyParameters : NtruPKeyParameters
    {
        private byte[] privKey;
        public byte[] PrivateKey => Arrays.Clone(privKey);

        public NtruPPrivateKeyParameters(NtruPParameters pParameters, byte[] privKey) : base(true, pParameters)
        {
            this.privKey = Arrays.Clone(privKey);
        }
        
        public byte[] GetEncoded()
        {
            return PrivateKey;
        }
    }
}