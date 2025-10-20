using Org.BouncyCastle.Crypto.Digests;

namespace Org.BouncyCastle.Crypto.Signers.MLDsa
{
    internal interface Symmetric
    {
        int Stream128BlockBytes { get; }
        int Stream256BlockBytes { get; }

        void Stream128Init(byte[] seed, ushort nonce);
        void Stream256Init(byte[] seed, ushort nonce);

        void Stream128SqueezeBlocks(byte[] output, int offset, int size);

        void Stream256SqueezeBlocks(byte[] output, int offset, int size);
    }

    internal sealed class ShakeSymmetric
        : Symmetric
    {
        private readonly ShakeDigest m_digest128 = new ShakeDigest(128);
        private readonly ShakeDigest m_digest256 = new ShakeDigest(256);

        public int Stream128BlockBytes => 168;

        public int Stream256BlockBytes => 136;

        public void Stream128Init(byte[] seed, ushort nonce)
        {
            StreamInit(m_digest128, seed, nonce);
        }

        public void Stream256Init(byte[] seed, ushort nonce)
        {
            StreamInit(m_digest256, seed, nonce);
        }

        public void Stream128SqueezeBlocks(byte[] output, int offset, int size)
        {
            m_digest128.Output(output, offset, size);
        }

        public void Stream256SqueezeBlocks(byte[] output, int offset, int size)
        {
            m_digest256.Output(output, offset, size);
        }

        private static void StreamInit(ShakeDigest digest, byte[] seed, ushort nonce)
        {
            byte[] temp = new byte[] { (byte)nonce, (byte)(nonce >> 8) };

            digest.Reset();
            digest.BlockUpdate(seed, 0, seed.Length);
            digest.BlockUpdate(temp, 0, temp.Length);
        }
    }
}
