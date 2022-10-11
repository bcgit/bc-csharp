using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium
{
    public abstract class Symmetric
    {
        public int Stream128BlockBytes;
        public int Stream256BlockBytes;
        
        Symmetric(int stream128, int stream256)
        {
            Stream128BlockBytes = stream128;
            Stream256BlockBytes = stream256;
        }
        
        internal abstract void Stream128Init(byte[] seed, ushort nonce);

        internal abstract void Stream256Init(byte[] seed, ushort nonce);

        internal abstract void Stream128SqueezeBlocks(byte[] output, int offset, int size);

        internal abstract void Stream256SqueezeBlocks(byte[] output, int offset, int size);
        
        internal class AesSymmetric
            : Symmetric
        {

            private SicBlockCipher cipher;

            public AesSymmetric()
                : base(64, 64)
            {
                cipher = new SicBlockCipher(AesUtilities.CreateEngine());
            }

            private void Aes128(byte[] output, int offset, int size)
            {
                byte[] buf = new byte[size];   // TODO: there might be a more efficient way of doing this...
                for (int i = 0; i < size; i+= 16)
                {
                    cipher.ProcessBlock(buf, i + offset, output, i + offset);
                }
            }

            private void StreamInit(byte[] key, ushort nonce)
            {
                byte[] expnonce = new byte[12];
                expnonce[0] = (byte)nonce;
                expnonce[1] = (byte)(nonce >> 8);
                
                ParametersWithIV kp = new ParametersWithIV(new KeyParameter(Arrays.CopyOfRange(key, 0, 32)), expnonce);
                cipher.Init(true, kp);
            }

            internal override void Stream128Init(byte[] seed, ushort nonce)
            {
                StreamInit(seed, nonce);
            }

            internal override void Stream256Init(byte[] seed, ushort nonce)
            {
                StreamInit(seed, nonce);
            }

            internal override void Stream128SqueezeBlocks(byte[] output, int offset, int size)
            {
                Aes128(output, offset, size);
            }

            internal override void Stream256SqueezeBlocks(byte[] output, int offset, int size)
            {
                Aes128(output, offset, size);
            }
        }


        internal class ShakeSymmetric
            : Symmetric
        {
            private ShakeDigest digest128;
            private ShakeDigest digest256;

            public ShakeSymmetric()
                : base(168, 136)
            {
                digest128 = new ShakeDigest(128);
                digest256 = new ShakeDigest(256);
            }

            private void StreamInit(ShakeDigest digest, byte[] seed, ushort nonce)
            {
                digest.Reset();
                byte[] temp = new byte[2];
                temp[0] = (byte)nonce;
                temp[1] = (byte)(nonce >> 8);

                digest.BlockUpdate(seed, 0, seed.Length);
                digest.BlockUpdate(temp, 0, temp.Length);
            }


            internal override void Stream128Init(byte[] seed, ushort nonce)
            {
                StreamInit(digest128, seed, nonce);
            }

            internal override void Stream256Init(byte[] seed, ushort nonce)
            {
                StreamInit(digest256, seed, nonce);
            }

            internal override void Stream128SqueezeBlocks(byte[] output, int offset, int size)
            {
                digest128.Output(output, offset, size);
            }

            internal override void Stream256SqueezeBlocks(byte[] output, int offset, int size)
            {
                digest256.Output(output, offset, size);
            }
        }
    }
}
