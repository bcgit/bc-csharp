using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Cmce
{
    public sealed class CmcePublicKeyParameters
        : CmceKeyParameters
    {
        internal readonly byte[] publicKey;

        public CmcePublicKeyParameters(CmceParameters parameters, byte[] publicKey)
            : base(false, parameters)
        {
            this.publicKey = Arrays.Clone(publicKey);
        }

        public byte[] GetPublicKey()
        { 
            return Arrays.Clone(publicKey);
        }

        public byte[] GetEncoded()
        {
            return GetPublicKey();
        }
    }
}
