using System;
using System.IO;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    public sealed class PgpPadding
        : PgpObject
    {
        public const int MaxPaddingLength = 255;
        public const int MinPaddingLength = 16;

        private readonly PaddingPacket m_packet;

        public PgpPadding(BcpgInputStream bcpgInput)
        {
            if (bcpgInput == null)
                throw new ArgumentNullException(nameof(bcpgInput));

            var packet = bcpgInput.ReadPacket();

            m_packet = packet as PaddingPacket ?? throw new IOException("unexpected packet in stream: " + packet);
        }

        public PgpPadding()
            : this((SecureRandom)null)
        {
        }

        public PgpPadding(SecureRandom random)
            : this(random.Next(MinPaddingLength, MaxPaddingLength), random)
        {
        }

        public PgpPadding(int paddingLength)
            : this(paddingLength, CryptoServicesRegistrar.GetSecureRandom())
        {
        }

        public PgpPadding(int paddingLength, SecureRandom random)
        {
            // TODO Range checks on paddingLength?

            m_packet = new PaddingPacket(paddingLength, CryptoServicesRegistrar.GetSecureRandom(random));
        }

        internal void Encode(BcpgOutputStream bcpgOutput) => m_packet.Encode(bcpgOutput);

        public void Encode(Stream outStr) => Encode(BcpgOutputStream.Wrap(outStr));

        public byte[] GetPadding() => m_packet.GetPadding();

        public byte[] GetEncoded()
        {
            var bOut = new MemoryStream();
            Encode(bOut);
            return bOut.ToArray();
        }

        internal PaddingPacket Packet => m_packet;
    }
}
