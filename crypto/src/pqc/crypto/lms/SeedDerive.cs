using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Lms
{
    // TODO[api] Make internal
    public sealed class SeedDerive
    {
        private readonly byte[] m_I;
        private readonly byte[] m_masterSeed;
        private readonly IDigest m_digest;

        public SeedDerive(byte[] I, byte[] masterSeed, IDigest digest)
        {
            m_I = I;
            m_masterSeed = masterSeed;
            m_digest = digest;
        }

        public byte[] GetI() => Arrays.Clone(m_I);

        public byte[] GetMasterSeed() => Arrays.Clone(m_masterSeed);

        public int J { get; set; }

        public int Q { get; set; }

        public byte[] DeriveSeed(bool incJ, byte[] target, int offset)
        {
            if (target.Length - offset < m_digest.GetDigestSize())
                throw new ArgumentException("target length is less than digest size.", nameof(target));

            int q = Q, j = J;

#pragma warning disable CS0618 // Type or member is obsolete
            m_digest.BlockUpdate(I, 0, I.Length);
#pragma warning restore CS0618 // Type or member is obsolete

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

#pragma warning disable CS0618 // Type or member is obsolete
            m_digest.BlockUpdate(m_masterSeed, 0, m_masterSeed.Length);
#pragma warning restore CS0618 // Type or member is obsolete

            m_digest.DoFinal(target, offset); // Digest resets here.

            if (incJ)
            {
                ++J;
            }

            return target;
        }

        [Obsolete("Use 'GetI' instead")]
        public byte[] I => m_I;

        [Obsolete("Use 'GetMasterSeed' instead")]
        public byte[] MasterSeed => m_masterSeed;
    }
}
