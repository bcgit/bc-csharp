using Org.BouncyCastle.Crypto.Digests;
using System;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber
{
    public abstract class Symmetric
    {
        internal readonly int XofBlockBytes;
        
        internal abstract void Hash_h(byte[] output, byte[] input, int outOffset);

        internal abstract void Hash_g(byte[] output, byte[] input);

        internal abstract void XofAbsorb(byte[] seed, byte x, byte y);

        internal abstract void XofSqueezeBlocks(byte[] output, int outOffset, int outLen);

        internal abstract void Prf(byte[] output, byte[] key, byte nonce);

        internal abstract void Kdf(byte[] output, byte[] input);

        Symmetric(int xofBlockBytes)
        {
            this.XofBlockBytes = xofBlockBytes;
        }

        internal class ShakeSymmetric
            : Symmetric
        {
            private ShakeDigest xof;
            private Sha3Digest sha3Digest512;
            private Sha3Digest sha3Digest256;
            private ShakeDigest shakeDigest;

            
            internal ShakeSymmetric()
                : base(164)
            {
                xof = new ShakeDigest(128);
                shakeDigest = new ShakeDigest(256);
                sha3Digest256 = new Sha3Digest(256);
                sha3Digest512 = new Sha3Digest(512);
            }

            internal override void Hash_h(byte[] output, byte[] input, int outOffset)
            {
                sha3Digest256.BlockUpdate(input, 0, input.Length);
                sha3Digest256.DoFinal(output, outOffset);
            }

            internal override void Hash_g(byte[] output, byte[] input)
            {
                sha3Digest512.BlockUpdate(input, 0, input.Length);
                sha3Digest512.DoFinal(output, 0);
            }

            internal override void XofAbsorb(byte[] seed, byte x, byte y)
            {
                xof.Reset();
                byte[] buf = new byte[seed.Length + 2];
                Array.Copy(seed, 0, buf, 0, seed.Length);
                buf[seed.Length] = x;
                buf[seed.Length + 1] = y;
                xof.BlockUpdate(buf, 0, seed.Length + 2);
            }

            internal override void XofSqueezeBlocks(byte[] output, int outOffset, int outLen)
            {
                xof.DoOutput(output, outOffset, outLen);
            }

            internal override void Prf(byte[] output, byte[] seed, byte nonce)
            {
                byte[] extSeed = new byte[seed.Length + 1];
                Array.Copy(seed, 0, extSeed, 0, seed.Length);
                extSeed[seed.Length] = nonce;
                shakeDigest.BlockUpdate(extSeed, 0, extSeed.Length);
                shakeDigest.DoFinal(output, 0, output.Length);
            }

            internal override void Kdf(byte[] output, byte[] input)
            {
                shakeDigest.BlockUpdate(input, 0, input.Length);
                shakeDigest.DoFinal(output, 0, output.Length);
            }
        }

        internal class AesSymmetric
            : Symmetric
        {
            private Sha256Digest sha256Digest;
            private Sha512Digest sha512Digest;
            private SicBlockCipher cipher;

            internal AesSymmetric()
                : base(64)
            {
                this.sha256Digest = new Sha256Digest();
                this.sha512Digest = new Sha512Digest();
                this.cipher = new SicBlockCipher(new AesEngine());
            }
            private void DoDigest(IDigest digest, byte[] output, byte[] input, int outOffset)
            {
                digest.BlockUpdate(input, 0, input.Length);
                digest.DoFinal(output, outOffset);
            }
            
            private void Aes128(byte[] output, int offset, int size)
            {
                byte[] buf = new byte[size + offset];   // TODO: there might be a more efficient way of doing this...
                for (int i = 0; i < size; i += 16)
                {
                    cipher.ProcessBlock(buf, i + offset, output, i + offset);
                }
            }
            
            internal override void Hash_h(byte[] output, byte[] input, int outOffset)
            {
                DoDigest(sha256Digest, output, input, outOffset);
            }

            internal override void Hash_g(byte[] output, byte[] input)
            {
                DoDigest(sha512Digest, output, input, 0);
            }

            internal override void XofAbsorb(byte[] key, byte x, byte y)
            {
                byte[] expnonce = new byte[12];
                expnonce[0] = x;
                expnonce[1] = y;

                ParametersWithIV kp = new ParametersWithIV(new KeyParameter(Arrays.CopyOfRange(key, 0, 32)), expnonce);
                cipher.Init(true, kp);
            }

            internal override void XofSqueezeBlocks(byte[] output, int outOffset, int outLen)
            {
                Aes128(output, outOffset, outLen);
            }

            internal override void Prf(byte[] output, byte[] key, byte nonce)
            {
                byte[] expnonce = new byte[12];
                expnonce[0] = nonce;

                ParametersWithIV kp = new ParametersWithIV(new KeyParameter(Arrays.CopyOfRange(key, 0, 32)), expnonce);
                cipher.Init(true, kp);
                Aes128(output, 0, output.Length);
            }

            internal override void Kdf(byte[] output, byte[] input)
            {
                byte[] buf = new byte[32];
                DoDigest(sha256Digest, buf, input, 0);
                Array.Copy(buf, 0, output, 0, output.Length);            
            }
        }

    }
}
