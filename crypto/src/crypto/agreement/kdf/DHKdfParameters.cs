using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Agreement.Kdf
{
    public class DHKdfParameters
        : IDerivationParameters
    {
        [Obsolete]
        internal static AlgorithmIdentifier WithDefaultParameters(string algorithm) =>
            WithDefaultParameters(new DerObjectIdentifier(algorithm));
        [Obsolete]
        internal static AlgorithmIdentifier WithDefaultParameters(DerObjectIdentifier algorithm) =>
            new AlgorithmIdentifier(algorithm, DerNull.Instance);

        private readonly AlgorithmIdentifier m_algID;
        private readonly int m_keySize;
        private readonly byte[] m_z;
        private readonly byte[] m_extraInfo;

        [Obsolete("Use '(AlgorithmIdentifier, ...)' instead")]
        public DHKdfParameters(DerObjectIdentifier algorithm, int keySize, byte[] z)
            : this(algorithm, keySize, z, extraInfo: null)
        {
        }

        [Obsolete("Use '(AlgorithmIdentifier, ...)' instead")]
        public DHKdfParameters(DerObjectIdentifier algorithm, int keySize, byte[] z, byte[] extraInfo)
            : this(WithDefaultParameters(algorithm), keySize, z, extraInfo)
        {
        }

        public DHKdfParameters(AlgorithmIdentifier algID, int keySize, byte[] z)
            : this(algID, keySize, z, extraInfo: null)
        {
        }

        public DHKdfParameters(AlgorithmIdentifier algID, int keySize, byte[] z, byte[] extraInfo)
        {
            m_algID = algID;
            m_keySize = keySize;
            m_z = Arrays.CopyBuffer(z);
            m_extraInfo = Arrays.Clone(extraInfo);
        }

        public AlgorithmIdentifier AlgID => m_algID;

        public DerObjectIdentifier Algorithm => m_algID.Algorithm;

        internal byte[] ExtraInfo => m_extraInfo;

        public byte[] GetZ() => Arrays.CopyBuffer(m_z);

        public byte[] GetExtraInfo() => Arrays.Clone(m_extraInfo);

        public int KeySize => m_keySize;

        internal byte[] Z => m_z;
    }
}
