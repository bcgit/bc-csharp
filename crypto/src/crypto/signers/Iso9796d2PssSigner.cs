using System;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Signers
{
    /// <summary> ISO9796-2 - mechanism using a hash function with recovery (scheme 2 and 3).
    /// <p>
    /// Note: the usual length for the salt is the length of the hash
    /// function used in bytes.</p>
    /// </summary>
    public class Iso9796d2PssSigner
        : ISignerWithRecovery
    {
        /// <summary>
        /// Return a reference to the recoveredMessage message.
        /// </summary>
        /// <returns>The full/partial recoveredMessage message.</returns>
        /// <seealso cref="ISignerWithRecovery.GetRecoveredMessage"/>
        public byte[] GetRecoveredMessage() => recoveredMessage;

        private IDigest digest;
        private IAsymmetricBlockCipher cipher;

        private SecureRandom random;
        private byte[] standardSalt;

        private int trailer;
        private int keyBits;
        private byte[] block;
        private byte[] mBuf;
        private int messageLength;
        private readonly int saltLength;
        private bool fullMessage;
        private byte[] recoveredMessage;

        private byte[] preSig;
        private byte[] preBlock;
        private int preMStart;
        private int preTLength;

        /// <summary>
        /// Generate a signer with either implicit or explicit trailer for ISO9796-2, scheme 2 or 3.
        /// </summary>
        /// <param name="cipher">base cipher to use for signature creation/verification</param>
        /// <param name="digest">digest to use.</param>
        /// <param name="saltLength">length of salt in bytes.</param>
        /// <param name="isImplicit">whether or not the trailer is implicit or gives the hash.</param>
        public Iso9796d2PssSigner(IAsymmetricBlockCipher cipher, IDigest digest, int saltLength, bool isImplicit)
        {
            this.cipher = cipher;
            this.digest = digest;
            this.saltLength = saltLength;

            if (isImplicit)
            {
                trailer = IsoTrailers.TRAILER_IMPLICIT;
            }
            else if (IsoTrailers.NoTrailerAvailable(digest))
            {
                throw new ArgumentException("no valid trailer", "digest");
            }
            else
            {
                trailer = IsoTrailers.GetTrailer(digest);
            }
        }

        /// <summary>
        /// Generate a signer with explicit trailer for ISO9796-2, scheme 2 or 3.
        /// </summary>
        /// <param name="cipher">base cipher to use for signature creation/verification</param>
        /// <param name="digest">digest to use.</param>
        /// <param name="saltLength">length of salt in bytes.</param>
        public Iso9796d2PssSigner(IAsymmetricBlockCipher cipher, IDigest digest, int saltLength)
            : this(cipher, digest, saltLength, isImplicit: false)
        {
        }

        public virtual string AlgorithmName => digest.AlgorithmName + "with" + "ISO9796-2S2";

        /// <summary>Initialise the signer.</summary>
        /// <param name="forSigning">true if for signing, false if for verification.</param>
        /// <param name="parameters">parameters for signature generation/verification. If the
        /// parameters are for generation they should be a ParametersWithRandom,
        /// a ParametersWithSalt, or just an RsaKeyParameters object. If RsaKeyParameters
        /// are passed in a SecureRandom will be created.
        /// </param>
        /// <exception cref="ArgumentException">if wrong parameter type or a fixed
        /// salt is passed in which is the wrong length.
        /// </exception>
        public virtual void Init(bool forSigning, ICipherParameters parameters)
        {
            RsaKeyParameters kParam;
            if (parameters is ParametersWithRandom withRandom)
            {
                kParam = (RsaKeyParameters)withRandom.Parameters;
                random = forSigning ? withRandom.Random : null;
            }
            else if (parameters is ParametersWithSalt withSalt)
            {
                if (!forSigning)
                    throw new ArgumentException("ParametersWithSalt only valid for signing", nameof(parameters));

                kParam = (RsaKeyParameters)withSalt.Parameters;
                standardSalt = withSalt.GetSalt();

                if (standardSalt.Length != saltLength)
                    throw new ArgumentException("Fixed salt is of wrong length");
            }
            else
            {
                kParam = (RsaKeyParameters)parameters;
                random = forSigning ? CryptoServicesRegistrar.GetSecureRandom() : null;
            }

            cipher.Init(forSigning, kParam);

            keyBits = kParam.Modulus.BitLength;

            block = new byte[(keyBits + 7) / 8];

            int tLength = trailer == IsoTrailers.TRAILER_IMPLICIT ? 1 : 2;
            mBuf = new byte[block.Length - digest.GetDigestSize() - saltLength - 1 - tLength];

            Reset();
        }

        /// <summary> compare two byte arrays - constant time.</summary>
        private bool IsSameAs(byte[] a, byte[] b)
        {
            return messageLength == b.Length &&
                   Arrays.FixedTimeEquals(messageLength, a, 0, b, 0);
        }

        /// <summary> clear possible sensitive data</summary>
        private void ClearBlock(byte[] block) => Array.Clear(block, 0, block.Length);

        public virtual void UpdateWithRecoveredMessage(byte[] signature)
        {
            byte[] block = cipher.ProcessBlock(signature, 0, signature.Length);

            //
            // adjust block size for leading zeroes if necessary
            //
            if (block.Length < (keyBits + 7) / 8)
            {
                byte[] tmp = new byte[(keyBits + 7) / 8];

                Array.Copy(block, 0, tmp, tmp.Length - block.Length, block.Length);
                ClearBlock(block);
                block = tmp;
            }

            int tLength;
            if (block[block.Length - 1] == 0xBC)
            {
                tLength = 1;
            }
            else
            {
                int sigTrail = Pack.BE_To_UInt16(block, block.Length - 2);

                if (IsoTrailers.NoTrailerAvailable(digest))
                    throw new ArgumentException("unrecognised hash in signature");

                if (sigTrail != IsoTrailers.GetTrailer(digest))
                    throw new InvalidOperationException("signer initialised with wrong digest for trailer " + sigTrail);

                tLength = 2;
            }

            int hLen = digest.GetDigestSize();

            //
            // remove the mask
            //
            int dbMaskLen = block.Length - hLen - tLength;
            byte[] dbMask = MaskGeneratorFunction1(block, dbMaskLen, hLen, dbMaskLen);
            Bytes.XorTo(dbMaskLen, dbMask, block);

            block[0] &= 0x7F;

            //
            // find out how much padding we've got
            //
            int mStart = 0;
            while (mStart < block.Length)
            {
                if (block[mStart++] == 0x01)
                    break;
            }

            if (mStart >= block.Length)
            {
                ClearBlock(block);
            }

            fullMessage = (mStart > 1);

            recoveredMessage = new byte[dbMask.Length - mStart - saltLength];

            Array.Copy(block, mStart, recoveredMessage, 0, recoveredMessage.Length);
            recoveredMessage.CopyTo(mBuf, 0);

            preSig = signature;
            preBlock = block;
            preMStart = mStart;
            preTLength = tLength;
        }

        /// <summary> update the internal digest with the byte b</summary>
        public virtual void Update(byte input)
        {
            if (preSig == null && messageLength < mBuf.Length)
            {
                mBuf[messageLength++] = input;
            }
            else
            {
                digest.Update(input);
            }
        }

        public virtual void BlockUpdate(byte[] input, int inOff, int inLen)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            BlockUpdate(input.AsSpan(inOff, inLen));
#else
            if (preSig == null)
            {
                while (inLen > 0 && messageLength < mBuf.Length)
                {
                    this.Update(input[inOff]);
                    inOff++;
                    inLen--;
                }
            }

            if (inLen > 0)
            {
                digest.BlockUpdate(input, inOff, inLen);
            }
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public virtual void BlockUpdate(ReadOnlySpan<byte> input)
        {
            if (preSig == null)
            {
                while (!input.IsEmpty && messageLength < mBuf.Length)
                {
                    this.Update(input[0]);
                    input = input[1..];
                }
            }

            if (!input.IsEmpty)
            {
                digest.BlockUpdate(input);
            }
        }
#endif

        public virtual int GetMaxSignatureSize() => cipher.GetOutputBlockSize();

        /// <summary> Generate a signature for the loaded message using the key we were
        /// initialised with.
        /// </summary>
        public virtual byte[] GenerateSignature()
        {
            byte[] salt = standardSalt ?? SecureRandom.GetNextBytes(random, saltLength);

            int hLen = digest.GetDigestSize();

            // calculate H(m2)
            byte[] hash = new byte[hLen];
            digest.DoFinal(hash, 0);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<byte> C = stackalloc byte[8];
            Pack.UInt64_To_BE((uint)(messageLength * 8), C);
            digest.BlockUpdate(C);
#else
            byte[] C = new byte[8];
            Pack.UInt64_To_BE((uint)(messageLength * 8), C);
            digest.BlockUpdate(C, 0, C.Length);
#endif

            if (messageLength > 0)
            {
                digest.BlockUpdate(mBuf, 0, messageLength);
            }

            digest.BlockUpdate(hash, 0, hash.Length);
            digest.BlockUpdate(salt, 0, salt.Length);
            digest.DoFinal(hash, 0);

            int tLength = 2;
            if (trailer == IsoTrailers.TRAILER_IMPLICIT)
            {
                tLength = 1;
            }

            int off = block.Length - messageLength - salt.Length - hLen - tLength - 1;

            block[off] = 0x01;

            Array.Copy(mBuf, 0, block, off + 1, messageLength);
            Array.Copy(salt, 0, block, off + 1 + messageLength, salt.Length);

            int dbMaskLen = block.Length - hLen - tLength;
            byte[] dbMask = MaskGeneratorFunction1(hash, 0, hash.Length, dbMaskLen);
            Bytes.XorTo(dbMaskLen, dbMask, block);

            Array.Copy(hash, 0, block, block.Length - hLen - tLength, hLen);

            if (trailer == IsoTrailers.TRAILER_IMPLICIT)
            {
                block[block.Length - 1] = (byte)IsoTrailers.TRAILER_IMPLICIT;
            }
            else
            {
                Pack.UInt16_To_BE((ushort)trailer, block, block.Length - 2);
            }

            block[0] &= 0x7F;

            byte[] b = cipher.ProcessBlock(block, 0, block.Length);

            ClearBlock(mBuf);
            ClearBlock(block);
            messageLength = 0;

            return b;
        }

        /// <summary> return true if the signature represents a ISO9796-2 signature
        /// for the passed in message.
        /// </summary>
        public virtual bool VerifySignature(byte[] signature)
        {
            int hLen = digest.GetDigestSize();

            // calculate H(m2)
            byte[] hash = new byte[hLen];
            digest.DoFinal(hash, 0);

            if (preSig == null)
            {
                try
                {
                    UpdateWithRecoveredMessage(signature);
                }
                catch (Exception)
                {
                    return false;
                }
            }
            else if (!Arrays.AreEqual(preSig, signature))
            {
                throw new InvalidOperationException("UpdateWithRecoveredMessage called on different signature");
            }

            byte[] block = preBlock;
            int mStart = preMStart;
            int tLength = preTLength;

            preSig = null;
            preBlock = null;

            //
            // check the hashes
            //
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<byte> C = stackalloc byte[8];
            Pack.UInt64_To_BE((uint)(recoveredMessage.Length * 8), C);
            digest.BlockUpdate(C);
#else
            byte[] C = new byte[8];
            Pack.UInt64_To_BE((uint)(recoveredMessage.Length * 8), C);
            digest.BlockUpdate(C, 0, C.Length);
#endif

            if (recoveredMessage.Length > 0)
            {
                digest.BlockUpdate(recoveredMessage, 0, recoveredMessage.Length);
            }

            digest.BlockUpdate(hash, 0, hash.Length);

            // Update for the salt
            if (standardSalt != null)
            {
                digest.BlockUpdate(standardSalt, 0, standardSalt.Length);
            }
            else
            {
                digest.BlockUpdate(block, mStart + recoveredMessage.Length, saltLength);
            }

            digest.DoFinal(hash, 0);

            bool isOkay = Arrays.FixedTimeEquals(hLen, hash, 0, block, block.Length - tLength - hLen);

            ClearBlock(block);
            ClearBlock(hash);

            if (!isOkay)
            {
                fullMessage = false;
                messageLength = 0;
                ClearBlock(recoveredMessage);
                return false;
            }

            //
            // if they've input a message check what we've recovered against
            // what was input.
            //
            bool result = messageLength == 0 || IsSameAs(mBuf, recoveredMessage);

            messageLength = 0;

            ClearBlock(mBuf);
            return result;
        }

        /// <summary> reset the internal state</summary>
        public virtual void Reset()
        {
            digest.Reset();
            messageLength = 0;
            if (mBuf != null)
            {
                ClearBlock(mBuf);
            }
            if (recoveredMessage != null)
            {
                ClearBlock(recoveredMessage);
                recoveredMessage = null;
            }
            fullMessage = false;
            if (preSig != null)
            {
                preSig = null;
                ClearBlock(preBlock);
                preBlock = null;
            }
        }

        /// <summary>
        /// Return true if the full message was recoveredMessage.
        /// </summary>
        /// <returns>true on full message recovery, false otherwise, or if not sure.</returns>
        /// <seealso cref="ISignerWithRecovery.HasFullMessage"/>
        public virtual bool HasFullMessage() => fullMessage;

        /// <summary> mask generator function, as described in Pkcs1v2.</summary>
        private byte[] MaskGeneratorFunction1(byte[] z, int zOff, int zLen, int length)
        {
            int hLen = digest.GetDigestSize();

            byte[] mask = new byte[length];
            byte[] buf = new byte[System.Math.Max(4, hLen)];
            uint counter = 0U;

            digest.Reset();

            int pos = 0, limit = length - hLen;
            while (pos <= limit)
            {
                Pack.UInt32_To_BE(counter++, buf);
                digest.BlockUpdate(z, zOff, zLen);
                digest.BlockUpdate(buf, 0, 4);
                digest.DoFinal(mask, pos);
                pos += hLen;
            }
            if (pos < length)
            {
                Pack.UInt32_To_BE(counter, buf);
                digest.BlockUpdate(z, zOff, zLen);
                digest.BlockUpdate(buf, 0, 4);
                digest.DoFinal(buf, 0);
                Array.Copy(buf, 0, mask, pos, length - pos);
            }

            return mask;
        }
    }
}
