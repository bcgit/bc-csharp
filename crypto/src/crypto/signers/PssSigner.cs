using System;

using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Signers
{
    /// <summary>RSA-PSS as described in Pkcs# 1 v 2.1.</summary>
    /// <remarks>
    /// The usual value for the salt length is the number of bytes in the hash function.
    /// </remarks>
    public class PssSigner
        : ISigner
    {
        public const byte TrailerImplicit = 0xBC;

        private readonly IDigest m_contentDigest1, m_contentDigest2;
        private readonly IDigest m_mgfDigest;
        private readonly IAsymmetricBlockCipher m_cipher;

        private SecureRandom m_random;

        private int hLen;
        private int mgfhLen;
        private int sLen;
        private bool sSet;
        private int emBits;
        private byte[] salt;
        private byte[] mDash;
        private byte[] block;
        private byte trailer;

        public static PssSigner CreateRawSigner(IAsymmetricBlockCipher cipher, IDigest digest)
        {
            return new PssSigner(cipher, Prehash.ForDigest(digest), digest, digest, digest.GetDigestSize(), null,
                TrailerImplicit);
        }

        public static PssSigner CreateRawSigner(IAsymmetricBlockCipher cipher, IDigest digest, int saltLen)
        {
            return new PssSigner(cipher, Prehash.ForDigest(digest), digest, digest, saltLen, null, TrailerImplicit);
        }

        public static PssSigner CreateRawSigner(IAsymmetricBlockCipher cipher, IDigest contentDigest, IDigest mgfDigest,
            int saltLen, byte trailer)
        {
            return new PssSigner(cipher, Prehash.ForDigest(contentDigest), contentDigest, mgfDigest, saltLen, null,
                trailer);
        }

        public static PssSigner CreateRawSigner(IAsymmetricBlockCipher cipher, IDigest contentDigest, IDigest mgfDigest,
            byte[] salt, byte trailer)
        {
            return new PssSigner(cipher, Prehash.ForDigest(contentDigest), contentDigest, mgfDigest, salt.Length, salt,
                trailer);
        }

        public PssSigner(IAsymmetricBlockCipher cipher, IDigest digest)
            : this(cipher, digest, digest.GetDigestSize())
        {
        }

        /// <summary>Basic constructor</summary>
        /// <param name="cipher">the asymmetric cipher to use.</param>
        /// <param name="digest">the digest to use.</param>
        /// <param name="saltLen">the length of the salt to use (in bytes).</param>
        public PssSigner(IAsymmetricBlockCipher cipher, IDigest digest, int saltLen)
            : this(cipher, digest, saltLen, TrailerImplicit)
        {
        }

        /// <summary>Basic constructor</summary>
        /// <param name="cipher">the asymmetric cipher to use.</param>
        /// <param name="digest">the digest to use.</param>
        /// <param name="salt">the fixed salt to be used.</param>
        public PssSigner(IAsymmetricBlockCipher cipher, IDigest digest, byte[] salt)
            : this(cipher, digest, digest, digest, salt.Length, salt, TrailerImplicit)
        {
        }

        public PssSigner(IAsymmetricBlockCipher cipher, IDigest contentDigest, IDigest mgfDigest, int saltLen)
            : this(cipher, contentDigest, mgfDigest, saltLen, TrailerImplicit)
        {
        }

        public PssSigner(IAsymmetricBlockCipher cipher, IDigest contentDigest, IDigest mgfDigest, byte[] salt)
            : this(cipher, contentDigest, contentDigest, mgfDigest, salt.Length, salt, TrailerImplicit)
        {
        }

        public PssSigner(IAsymmetricBlockCipher cipher, IDigest digest, int saltLen, byte trailer)
            : this(cipher, digest, digest, saltLen, trailer)
        {
        }

        public PssSigner(IAsymmetricBlockCipher cipher, IDigest contentDigest, IDigest mgfDigest, int saltLen,
            byte trailer)
            : this(cipher, contentDigest, contentDigest, mgfDigest, saltLen, null, trailer)
        {
        }

        private PssSigner(IAsymmetricBlockCipher cipher, IDigest contentDigest1, IDigest contentDigest2,
            IDigest mgfDigest, int saltLen, byte[] salt, byte trailer)
        {
            m_cipher = cipher;
            m_contentDigest1 = contentDigest1;
            m_contentDigest2 = contentDigest2;
            m_mgfDigest = mgfDigest;
            this.hLen = contentDigest2.GetDigestSize();
            this.mgfhLen = mgfDigest.GetDigestSize();
            this.sLen = saltLen;
            this.sSet = salt != null;
            if (sSet)
            {
                this.salt = salt;
            }
            else
            {
                this.salt = new byte[saltLen];
            }
            this.mDash = new byte[8 + saltLen + hLen];
            this.trailer = trailer;
        }

        public virtual string AlgorithmName => m_mgfDigest.AlgorithmName + "withRSAandMGF1";

        public virtual void Init(bool forSigning, ICipherParameters parameters)
        {
            m_cipher.Init(forSigning, parameters);

            parameters = ParameterUtilities.GetRandom(parameters, out var providedRandom);

            // TODO Only needed if salt generation needed?
            m_random = forSigning ? CryptoServicesRegistrar.GetSecureRandom(providedRandom) : null;

            RsaKeyParameters kParam;
            if (parameters is RsaBlindingParameters blinding)
            {
                kParam = blinding.PublicKey;
            }
            else
            {
                kParam = (RsaKeyParameters)parameters;
            }

            emBits = kParam.Modulus.BitLength - 1;

            if (emBits < (8 * hLen + 8 * sLen + 9))
                throw new ArgumentException("key too small for specified hash and salt lengths");

            block = new byte[(emBits + 7) / 8];
        }

        /// <summary> clear possible sensitive data</summary>
        private void ClearBlock(byte[] block) => Arrays.ZeroMemory(block);

        public virtual void Update(byte input) => m_contentDigest1.Update(input);

        public virtual void BlockUpdate(byte[] input, int inOff, int inLen) =>
            m_contentDigest1.BlockUpdate(input, inOff, inLen);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public virtual void BlockUpdate(ReadOnlySpan<byte> input) => m_contentDigest1.BlockUpdate(input);
#endif

        public virtual int GetMaxSignatureSize() => m_cipher.GetOutputBlockSize();

        public virtual byte[] GenerateSignature()
        {
            if (m_contentDigest1.GetDigestSize() != hLen)
                throw new InvalidOperationException();

            m_contentDigest1.DoFinal(mDash, mDash.Length - hLen - sLen);

            if (sLen != 0)
            {
                if (!sSet)
                {
                    m_random.NextBytes(salt);
                }
                salt.CopyTo(mDash, mDash.Length - sLen);
            }

            byte[] h = new byte[hLen];

            m_contentDigest2.BlockUpdate(mDash, 0, mDash.Length);

            m_contentDigest2.DoFinal(h, 0);

            block[block.Length - sLen - 1 - hLen - 1] = (byte)(0x01);
            salt.CopyTo(block, block.Length - sLen - hLen - 1);

            byte[] dbMask = MaskGeneratorFunction(h, 0, h.Length, block.Length - hLen - 1);
            for (int i = 0; i != dbMask.Length; i++)
            {
                block[i] ^= dbMask[i];
            }

            h.CopyTo(block, block.Length - hLen - 1);

            uint firstByteMask = 0xFFU >> ((block.Length * 8) - emBits);

            block[0] &= (byte)firstByteMask;
            block[block.Length - 1] = trailer;

            byte[] b = m_cipher.ProcessBlock(block, 0, block.Length);

            ClearBlock(block);

            return b;
        }

        public virtual bool VerifySignature(byte[] signature)
        {
            if (m_contentDigest1.GetDigestSize() != hLen)
                throw new InvalidOperationException();

            m_contentDigest1.DoFinal(mDash, mDash.Length - hLen - sLen);

            byte[] b = m_cipher.ProcessBlock(signature, 0, signature.Length);
            Arrays.Fill(block, 0, block.Length - b.Length, 0);
            b.CopyTo(block, block.Length - b.Length);

            uint firstByteMask = 0xFFU >> ((block.Length * 8) - emBits);

            if (block[0] != (byte)(block[0] & firstByteMask) ||
                block[block.Length - 1] != trailer)
            {
                ClearBlock(block);
                return false;
            }

            byte[] dbMask = MaskGeneratorFunction(block, block.Length - hLen - 1, hLen, block.Length - hLen - 1);

            for (int i = 0; i != dbMask.Length; i++)
            {
                block[i] ^= dbMask[i];
            }

            block[0] &= (byte)firstByteMask;

            for (int i = 0; i != block.Length - hLen - sLen - 2; i++)
            {
                if (block[i] != 0)
                {
                    ClearBlock(block);
                    return false;
                }
            }

            if (block[block.Length - hLen - sLen - 2] != 0x01)
            {
                ClearBlock(block);
                return false;
            }

            if (sSet)
            {
                Array.Copy(salt, 0, mDash, mDash.Length - sLen, sLen);
            }
            else
            {
                Array.Copy(block, block.Length - sLen - hLen - 1, mDash, mDash.Length - sLen, sLen);
            }

            m_contentDigest2.BlockUpdate(mDash, 0, mDash.Length);
            m_contentDigest2.DoFinal(mDash, mDash.Length - hLen);

            for (int i = block.Length - hLen - 1, j = mDash.Length - hLen; j != mDash.Length; i++, j++)
            {
                if ((block[i] ^ mDash[j]) != 0)
                {
                    ClearBlock(mDash);
                    ClearBlock(block);
                    return false;
                }
            }

            ClearBlock(mDash);
            ClearBlock(block);

            return true;
        }

        public virtual void Reset() => m_contentDigest1.Reset();

        private byte[] MaskGeneratorFunction(byte[] z, int zOff, int zLen, int length)
        {
            if (m_mgfDigest is IXof xof)
            {
                byte[] mask = new byte[length];
                xof.BlockUpdate(z, zOff, zLen);
                xof.OutputFinal(mask, 0, mask.Length);
                return mask;
            }

            return MaskGeneratorFunction1(z, zOff, zLen, length);
        }

        /// <summary> mask generator function, as described in Pkcs1v2.</summary>
        private byte[] MaskGeneratorFunction1(byte[] z, int zOff, int zLen, int length)
        {
            byte[] mask = new byte[length];

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<byte> Z = z.AsSpan(zOff, zLen);
            Span<byte> C = stackalloc byte[4];
#else
            byte[] C = new byte[4];
#endif

            uint counter = 0U;
            int pos = 0;

            m_mgfDigest.Reset();

            while (pos <= length - mgfhLen)
            {
                Pack.UInt32_To_BE(counter++, C);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                m_mgfDigest.BlockUpdate(Z);
                m_mgfDigest.BlockUpdate(C);
#else
                m_mgfDigest.BlockUpdate(z, zOff, zLen);
                m_mgfDigest.BlockUpdate(C, 0, C.Length);
#endif

                m_mgfDigest.DoFinal(mask, pos);
                pos += mgfhLen;
            }

            if (pos < length)
            {
                Pack.UInt32_To_BE(counter, C);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                m_mgfDigest.BlockUpdate(Z);
                m_mgfDigest.BlockUpdate(C);
#else
                m_mgfDigest.BlockUpdate(z, zOff, zLen);
                m_mgfDigest.BlockUpdate(C, 0, C.Length);
#endif

                byte[] hashBuf = new byte[mgfhLen];
                m_mgfDigest.DoFinal(hashBuf, 0);
                Array.Copy(hashBuf, 0, mask, pos, mask.Length - pos);
            }

            return mask;
        }
    }
}
