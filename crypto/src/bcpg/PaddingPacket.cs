using System;

using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Bcpg
{
    public class PaddingPacket
        : ContainedPacket
    {
        private readonly byte[] m_padding;

        internal PaddingPacket(BcpgInputStream bcpgIn)
            : this(bcpgIn, newPacketFormat: true)
        {
        }

        internal PaddingPacket(BcpgInputStream bcpgIn, bool newPacketFormat)
            : base(PacketTag.Padding, newPacketFormat)
        {
            if (bcpgIn == null)
                throw new ArgumentNullException(nameof(bcpgIn));

            m_padding = Streams.ReadAll(bcpgIn);
        }

        /// <summary>Create a new <see cref="PaddingPacket"/>.</summary>
        /// <param name="padding">The padding.</param>
        public PaddingPacket(byte[] padding)
            : base(PacketTag.Padding, newPacketFormat: true)
        {
            m_padding = Arrays.CopyBuffer(padding);
        }

        /// <summary>Create a new <see cref="PaddingPacket"/>.</summary>
        /// <param name="paddingLength">The padding length.</param>
        /// <param name="random">The source of randomness.</param>
        public PaddingPacket(int paddingLength, SecureRandom random)
            : base(PacketTag.Padding, newPacketFormat: true)
        {
            if (paddingLength < 1)
                throw new ArgumentOutOfRangeException(nameof(paddingLength));
            if (random == null)
                throw new ArgumentNullException(nameof(random));

            m_padding = SecureRandom.GetNextBytes(random, paddingLength);
        }

        /// <inheritdoc/>
        public override void Encode(BcpgOutputStream bcpgOut) =>
            bcpgOut.WritePacket(HasNewPacketFormat, PacketTag.Padding, m_padding);

        /// <summary>Return the padding.</summary>
        public byte[] GetPadding() => Arrays.InternalCopyBuffer(m_padding);

        internal byte[] Padding => m_padding;
    }
}
