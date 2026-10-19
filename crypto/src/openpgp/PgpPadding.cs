using System;
using System.IO;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <summary>A padding packet.</summary>
    public sealed class PgpPadding
        : PgpObject
    {
        /// <summary>The <c>MaxPaddingLength</c> constant, with the value <c>255</c>.</summary>
        public const int MaxPaddingLength = 255;
        /// <summary>The <c>MinPaddingLength</c> constant, with the value <c>16</c>.</summary>
        public const int MinPaddingLength = 16;

        private readonly PaddingPacket m_packet;

        /// <summary>Create a new <see cref="PgpPadding"/>.</summary>
        /// <param name="bcpgInput">The bcpg input.</param>
        public PgpPadding(BcpgInputStream bcpgInput)
        {
            if (bcpgInput == null)
                throw new ArgumentNullException(nameof(bcpgInput));

            var packet = bcpgInput.ReadPacket();

            m_packet = packet as PaddingPacket ?? throw new IOException("unexpected packet in stream: " + packet);
        }

        /// <summary>Create a new <see cref="PgpPadding"/>.</summary>
        public PgpPadding()
            : this((SecureRandom)null)
        {
        }

        /// <summary>Create a new <see cref="PgpPadding"/>.</summary>
        /// <param name="random">The source of randomness.</param>
        public PgpPadding(SecureRandom random)
            : this(random.Next(MinPaddingLength, MaxPaddingLength), random)
        {
        }

        /// <summary>Create a new <see cref="PgpPadding"/>.</summary>
        /// <param name="paddingLength">The padding length.</param>
        public PgpPadding(int paddingLength)
            : this(paddingLength, CryptoServicesRegistrar.GetSecureRandom())
        {
        }

        /// <summary>Create a new <see cref="PgpPadding"/>.</summary>
        /// <param name="paddingLength">The padding length.</param>
        /// <param name="random">The source of randomness.</param>
        public PgpPadding(int paddingLength, SecureRandom random)
        {
            // TODO Range checks on paddingLength?

            m_packet = new PaddingPacket(paddingLength, CryptoServicesRegistrar.GetSecureRandom(random));
        }

        internal void Encode(BcpgOutputStream bcpgOutput) => m_packet.Encode(bcpgOutput);

        /// <summary>Write the encoding of this object.</summary>
        /// <param name="outStr">The stream to write to.</param>
        public void Encode(Stream outStr) => Encode(BcpgOutputStream.Wrap(outStr));

        /// <summary>Return the padding.</summary>
        public byte[] GetPadding() => m_packet.GetPadding();

        /// <summary>Return the encoded.</summary>
        public byte[] GetEncoded()
        {
            var bOut = new MemoryStream();
            Encode(bOut);
            return bOut.ToArray();
        }

        internal PaddingPacket Packet => m_packet;
    }
}
