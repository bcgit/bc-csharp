using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg
{
    public class PaddingPacket
        : ContainedPacket
    {
        private readonly byte[] padding;

        public PaddingPacket(BcpgInputStream bcpgIn)
        {
            padding = bcpgIn.ReadAll();
        }

        public PaddingPacket(int length, BcpgInputStream bcpgIn)
        {
            padding = new byte[length];
            bcpgIn.ReadFully(padding);
        }

        public PaddingPacket(byte[] padding)
        {
            this.padding = Arrays.Clone(padding);
        }

        public PaddingPacket(int length, SecureRandom random)
            : this(RandomBytes(length, random))
        {
        }

        private static byte[] RandomBytes(int length, SecureRandom random)
        {
            byte[] bytes = new byte[length];
            random.NextBytes(bytes);
            return bytes;
        }

        public byte[] GetPadding()
        {
            return Arrays.Clone(padding);
        }

        public override void Encode(BcpgOutputStream bcpgOut)
        {
            bcpgOut.WritePacket(PacketTag.Padding, padding);
        }
    }
}