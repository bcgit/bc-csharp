using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Cmce
{
    /// <summary>A Classic McEliece public (encapsulation) key, represented by its raw byte encoding.</summary>
    public sealed class CmcePublicKeyParameters
        : CmceKeyParameters
    {
        internal readonly byte[] publicKey;

        /// <summary>Creates a Classic McEliece public key from its raw encoding.</summary>
        /// <param name="parameters">The Classic McEliece parameter set this key belongs to.</param>
        /// <param name="publicKey">The raw public key bytes; a defensive copy is taken.</param>
        public CmcePublicKeyParameters(CmceParameters parameters, byte[] publicKey)
            : base(false, parameters)
        {
            this.publicKey = Arrays.Clone(publicKey);
        }

        /// <summary>Returns a copy of the raw public key bytes.</summary>
        public byte[] GetPublicKey()
        {
            return Arrays.Clone(publicKey);
        }

        /// <summary>Returns a copy of the raw public key encoding.</summary>
        public byte[] GetEncoded()
        {
            return GetPublicKey();
        }
    }
}
