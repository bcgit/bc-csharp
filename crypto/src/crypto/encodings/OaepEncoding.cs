using System;

using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Encodings
{
    /**
    * Optimal Asymmetric Encryption Padding (OAEP) - see PKCS 1 V 2.
    */
    public class OaepEncoding
        : IAsymmetricBlockCipher
    {
        private static int GetMgf1NoMemoLimit(IDigest d)
        {
            if (d is IMemoable)
                return d.GetByteLength() - 1;

            return int.MaxValue;
        }

        private readonly IAsymmetricBlockCipher engine;
        private readonly IDigest mgf1Hash;
        private readonly int mgf1NoMemoLimit;
        private readonly byte[] defHash;

        private SecureRandom random;
        private bool forEncryption;

        public OaepEncoding(IAsymmetricBlockCipher cipher)
            : this(cipher, new Sha1Digest(), null)
        {
        }

        public OaepEncoding(IAsymmetricBlockCipher cipher, IDigest hash)
            : this(cipher, hash, null)
        {
        }

        public OaepEncoding(IAsymmetricBlockCipher cipher, IDigest hash, byte[] encodingParams)
            : this(cipher, hash, hash, encodingParams)
        {
        }

        public OaepEncoding(IAsymmetricBlockCipher cipher, IDigest hash, IDigest mgf1Hash, byte[] encodingParams)
        {
            this.engine = cipher;
            this.mgf1Hash = mgf1Hash;
            this.mgf1NoMemoLimit = GetMgf1NoMemoLimit(mgf1Hash);
            this.defHash = new byte[hash.GetDigestSize()];

            hash.Reset();

            if (encodingParams != null)
            {
                hash.BlockUpdate(encodingParams, 0, encodingParams.Length);
            }

            hash.DoFinal(defHash, 0);
        }

        public string AlgorithmName => engine.AlgorithmName + "/OAEPPadding";

        public IAsymmetricBlockCipher UnderlyingCipher => engine;

        public void Init(bool forEncryption, ICipherParameters parameters)
        {
            SecureRandom initRandom = null;
            if (parameters is ParametersWithRandom withRandom)
            {
                initRandom = withRandom.Random;
            }

            this.random = forEncryption ? CryptoServicesRegistrar.GetSecureRandom(initRandom) : null;
            this.forEncryption = forEncryption;

            engine.Init(forEncryption, parameters);
        }

        public int GetInputBlockSize()
        {
            int baseBlockSize = engine.GetInputBlockSize();

            if (forEncryption)
            {
                return baseBlockSize - 1 - 2 * defHash.Length;
            }
            else
            {
                return baseBlockSize;
            }
        }

        public int GetOutputBlockSize()
        {
            int baseBlockSize = engine.GetOutputBlockSize();

            if (forEncryption)
            {
                return baseBlockSize;
            }
            else
            {
                return baseBlockSize - 1 - 2 * defHash.Length;
            }
        }

        public byte[] ProcessBlock(byte[] inBytes, int inOff, int inLen)
        {
            return forEncryption
                ? EncodeBlock(inBytes, inOff, inLen)
                : DecodeBlock(inBytes, inOff, inLen);
        }

        private byte[] EncodeBlock(byte[] inBytes, int inOff, int inLen)
        {
            int inputBlockSize = GetInputBlockSize();
            Check.DataLength(inLen > inputBlockSize, "input data too long");

            byte[] block = new byte[inputBlockSize + 1 + 2 * defHash.Length];

            //
            // copy in the message
            //
            Array.Copy(inBytes, inOff, block, block.Length - inLen, inLen);

            //
            // add sentinel
            //
            block[block.Length - inLen - 1] = 0x01;

            //
            // as the block is already zeroed - there's no need to add PS (the >= 0 pad of 0)
            //

            //
            // add the hash of the encoding params.
            //
            Array.Copy(defHash, 0, block, defHash.Length, defHash.Length);

            //
            // generate the seed.
            //
            random.NextBytes(block, 0, defHash.Length);

            mgf1Hash.Reset();

            //
            // mask the message block.
            //
            MaskGeneratorFunction(block, 0, defHash.Length, block, defHash.Length, block.Length - defHash.Length);

            //
            // mask the seed.
            //
            MaskGeneratorFunction(block, defHash.Length, block.Length - defHash.Length, block, 0, defHash.Length);

            return engine.ProcessBlock(block, 0, block.Length);
        }

        /**
        * @exception InvalidCipherTextException if the decrypted block turns out to
        * be badly formatted.
        */
        private byte[] DecodeBlock(byte[] inBytes, int inOff, int inLen)
        {
            // i.e. wrong when block.length < (2 * defHash.length) + 1
            int wrongMask = GetOutputBlockSize() >> 31;

            //
            // as we may have zeros in our leading bytes for the block we produced
            // on encryption, we need to make sure our decrypted block comes back
            // the same size.
            //
            byte[] block = new byte[engine.GetOutputBlockSize()];
            {
                byte[] data = engine.ProcessBlock(inBytes, inOff, inLen);
                wrongMask |= (block.Length - data.Length) >> 31;

                int copyLen = System.Math.Min(block.Length, data.Length);
                Array.Copy(data, 0, block, block.Length - copyLen, copyLen);
                Array.Clear(data, 0, data.Length);
            }

            mgf1Hash.Reset();

            //
            // unmask the seed.
            //
            MaskGeneratorFunction(block, defHash.Length, block.Length - defHash.Length, block, 0, defHash.Length);

            //
            // unmask the message block.
            //
            MaskGeneratorFunction(block, 0, defHash.Length, block, defHash.Length, block.Length - defHash.Length);

            //
            // check the hash of the encoding params.
            // long check to try to avoid this been a source of a timing attack.
            //
            for (int i = 0; i != defHash.Length; i++)
            {
                wrongMask |= defHash[i] ^ block[defHash.Length + i];
            }

            //
            // find the data block
            //
            int start = -1;

            for (int index = 2 * defHash.Length; index != block.Length; index++)
            {
                int octet = block[index];

                // i.e. mask will be 0xFFFFFFFF if octet is non-zero and start is (still) negative, else 0.
                int shouldSetMask = (-octet & start) >> 31;

                start += index & shouldSetMask;
            }

            wrongMask |= start >> 31;
            ++start;
            wrongMask |= block[start] ^ 1;

            if (wrongMask != 0)
            {
                Array.Clear(block, 0, block.Length);
                throw new InvalidCipherTextException("data wrong");
            }

            ++start;

            //
            // extract the data block
            //
            byte[] output = new byte[block.Length - start];

            Array.Copy(block, start, output, 0, output.Length);
            Array.Clear(block, 0, block.Length);

            return output;
        }

        private void MaskGeneratorFunction(byte[] z, int zOff, int zLen, byte[] mask, int maskOff, int maskLen)
        {
            if (mgf1Hash is IXof xof)
            {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                Span<byte> buf = maskLen <= 512
                    ? stackalloc byte[maskLen]
                    : new byte[maskLen];
                xof.BlockUpdate(z, zOff, zLen);
                xof.OutputFinal(buf);
                Bytes.XorTo(maskLen, buf, mask.AsSpan(maskOff));
#else
                byte[] buf = new byte[maskLen];
                xof.BlockUpdate(z, zOff, zLen);
                xof.OutputFinal(buf, 0, maskLen);
                Bytes.XorTo(maskLen, buf, 0, mask, maskOff);
#endif
            }
            else
            {
                MaskGeneratorFunction1(z, zOff, zLen, mask, maskOff, maskLen);
            }
        }

        /**
        * mask generator function, as described in PKCS1v2.
        */
        private void MaskGeneratorFunction1(byte[] z, int zOff, int zLen, byte[] mask, int maskOff, int maskLen)
        {
            int digestSize = mgf1Hash.GetDigestSize();

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<byte> hash = digestSize <= 128
                ? stackalloc byte[digestSize]
                : new byte[digestSize];
            Span<byte> C = stackalloc byte[4];
#else
            byte[] hash = new byte[digestSize];
            byte[] C = new byte[4];
#endif
            int counter = 0;

            int maskEnd = maskOff + maskLen;
            int maskLimit = maskEnd - digestSize;
            int maskPos = maskOff;

            mgf1Hash.BlockUpdate(z, zOff, zLen);

            if (zLen > mgf1NoMemoLimit)
            {
                IMemoable memoable = (IMemoable)mgf1Hash;
                IMemoable memo = memoable.Copy();

                while (maskPos < maskLimit)
                {
                    Pack.UInt32_To_BE((uint)counter++, C);
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                    mgf1Hash.BlockUpdate(C);
                    mgf1Hash.DoFinal(hash);
                    memoable.Reset(memo);
                    Bytes.XorTo(digestSize, hash, mask.AsSpan(maskPos));
#else
                    mgf1Hash.BlockUpdate(C, 0, C.Length);
                    mgf1Hash.DoFinal(hash, 0);
                    memoable.Reset(memo);
                    Bytes.XorTo(digestSize, hash, 0, mask, maskPos);
#endif
                    maskPos += digestSize;
                }
            }
            else
            {
                while (maskPos < maskLimit)
                {
                    Pack.UInt32_To_BE((uint)counter++, C);
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                    mgf1Hash.BlockUpdate(C);
                    mgf1Hash.DoFinal(hash);
                    mgf1Hash.BlockUpdate(z, zOff, zLen);
                    Bytes.XorTo(digestSize, hash, mask.AsSpan(maskPos));
#else
                    mgf1Hash.BlockUpdate(C, 0, C.Length);
                    mgf1Hash.DoFinal(hash, 0);
                    mgf1Hash.BlockUpdate(z, zOff, zLen);
                    Bytes.XorTo(digestSize, hash, 0, mask, maskPos);
#endif
                    maskPos += digestSize;
                }
            }

            Pack.UInt32_To_BE((uint)counter, C);
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            mgf1Hash.BlockUpdate(C);
            mgf1Hash.DoFinal(hash);
            Bytes.XorTo(maskEnd - maskPos, hash, mask.AsSpan(maskPos));
#else
            mgf1Hash.BlockUpdate(C, 0, C.Length);
            mgf1Hash.DoFinal(hash, 0);
            Bytes.XorTo(maskEnd - maskPos, hash, 0, mask, maskPos);
#endif
        }
    }
}
