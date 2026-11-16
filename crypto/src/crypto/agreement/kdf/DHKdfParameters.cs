using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Agreement.Kdf
{
    /// <summary>Parameters for the key derivation function used with Diffie-Hellman key agreement.</summary>
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

        /// <summary>Create a new <see cref="DHKdfParameters"/>.</summary>
        /// <param name="algorithm">The algorithm.</param>
        /// <param name="keySize">The key size in bits.</param>
        /// <param name="z">The result.</param>
        [Obsolete("Use '(AlgorithmIdentifier, ...)' instead")]
        public DHKdfParameters(DerObjectIdentifier algorithm, int keySize, byte[] z)
            : this(algorithm, keySize, z, extraInfo: null)
        {
        }

        /// <summary>Create a new <see cref="DHKdfParameters"/>.</summary>
        /// <param name="algorithm">The algorithm.</param>
        /// <param name="keySize">The key size in bits.</param>
        /// <param name="z">The result.</param>
        /// <param name="extraInfo">The extra info.</param>
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

        /// <summary>Gets the algorithm.</summary>
        public DerObjectIdentifier Algorithm => m_algID.Algorithm;

        internal byte[] ExtraInfo => m_extraInfo;

        /// <summary>Return the z.</summary>
        public byte[] GetZ() => Arrays.CopyBuffer(m_z);

        /// <summary>Return the extra info.</summary>
        public byte[] GetExtraInfo() => Arrays.Clone(m_extraInfo);

        /// <summary>Gets the key size.</summary>
        public int KeySize => m_keySize;

        internal byte[] Z => m_z;
    }
}
