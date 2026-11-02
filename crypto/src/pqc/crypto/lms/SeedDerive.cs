using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Lms
{
    /// <summary>The derivation of the one-time signature seeds of an LMS tree from the root seed.</summary>
    // TODO[api] Make internal
    public sealed class SeedDerive
    {
        private readonly byte[] m_I;
        private readonly byte[] m_masterSeed;
        private readonly IDigest m_digest;

        /// <summary>Create a new <see cref="SeedDerive"/>.</summary>
        /// <param name="I">The i.</param>
        /// <param name="masterSeed">The master seed.</param>
        /// <param name="digest">The digest.</param>
        public SeedDerive(byte[] I, byte[] masterSeed, IDigest digest)
        {
            m_I = I;
            m_masterSeed = masterSeed;
            m_digest = digest;
        }

        /// <summary>Return the i.</summary>
        public byte[] GetI() => Arrays.Clone(m_I);

        /// <summary>Return the master seed.</summary>
        public byte[] GetMasterSeed() => Arrays.Clone(m_masterSeed);

        /// <summary>Gets or sets the j.</summary>
        public int J { get; set; }

        /// <summary>Gets or sets the q.</summary>
        public int Q { get; set; }

        /// <summary>Derive a seed.</summary>
        /// <param name="incJ">true to increment the counter j afterwards.</param>
        /// <param name="target">The buffer to receive the seed.</param>
        /// <param name="offset">The offset into <paramref name="target"/> at which to start writing.</param>
        /// <returns>The target buffer.</returns>
        public byte[] DeriveSeed(bool incJ, byte[] target, int offset)
        {
            if (target.Length - offset < m_digest.GetDigestSize())
                throw new ArgumentException("target length is less than digest size.", nameof(target));

            int q = Q, j = J;

            m_digest.BlockUpdate(m_I, 0, m_I.Length);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<byte> qj = stackalloc byte[7];
            Pack.UInt32_To_BE((uint)q, qj);
            Pack.UInt16_To_BE((ushort)j, qj[4..]);
            qj[6] = 0xFF;
            m_digest.BlockUpdate(qj);
#else
            m_digest.Update((byte)(q >> 24));
            m_digest.Update((byte)(q >> 16));
            m_digest.Update((byte)(q >> 8));
            m_digest.Update((byte)(q));

            m_digest.Update((byte)(j >> 8));
            m_digest.Update((byte)(j));
            m_digest.Update(0xFF);
#endif

            m_digest.BlockUpdate(m_masterSeed, 0, m_masterSeed.Length);

            m_digest.DoFinal(target, offset); // Digest resets here.

            if (incJ)
            {
                ++J;
            }

            return target;
        }

        /// <summary>Gets the i.</summary>
        [Obsolete("Use 'GetI' instead")]
        public byte[] I => m_I;

        /// <summary>Gets the master seed.</summary>
        [Obsolete("Use 'GetMasterSeed' instead")]
        public byte[] MasterSeed => m_masterSeed;
    }
}
