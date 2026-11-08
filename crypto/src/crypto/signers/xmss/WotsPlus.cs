using System;
using System.Collections.Generic;

using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Signers.Xmss
{
    /// <summary>WOTS+.</summary>
    internal sealed class WotsPlus
    {
        /// <summary>
        /// The length RFC 8391 sec. 4.1.2 fixes PRF's second argument at - the 32 bytes of an
        /// <see cref="XmssAddress"/> encoding, and the width <see cref="ExpandSecretKeySeed"/> writes an index in.
        /// </summary>
        private const int PrfIndexSize = 32;

        /// <summary>WOTS+ parameters.</summary>
        private readonly WotsPlusParameters m_params;
        /// <summary>Randomization functions.</summary>
        private readonly KeyedHashFunctions m_khf;
        /// <summary>WOTS+ secret key seed.</summary>
        private readonly byte[] m_secretKeySeed;
        /// <summary>WOTS+ public seed.</summary>
        private readonly byte[] m_publicSeed;

        /// <summary>
        /// Constructs a new WOTS+ one-time signature system based on the given WOTS+ parameters.
        /// </summary>
        /// <param name="parameters">Parameters for WOTSPlus object.</param>
        internal WotsPlus(WotsPlusParameters parameters)
        {
            m_params = parameters;
            int n = parameters.TreeDigestSize;
            m_khf = new KeyedHashFunctions(parameters.TreeDigest, n);
            m_secretKeySeed = new byte[n];
            m_publicSeed = new byte[n];
        }

        /// <summary>Import keys to WOTS+ instance.</summary>
        /// <remarks>
        /// The seeds are copied in rather than taken by reference, so a caller that keeps its own array cannot
        /// change this instance's key material after importing it. An absent seed is rejected rather than
        /// replaced by an all-zero one.
        /// </remarks>
        /// <param name="secretKeySeed">Secret key seed.</param>
        /// <param name="publicSeed">Public seed.</param>
        internal void ImportKeys(byte[] secretKeySeed, byte[] publicSeed)
        {
            int n = m_params.TreeDigestSize;

            XmssUtilities.ValidateSize(secretKeySeed, n, "secretKeySeed");
            XmssUtilities.ValidateSize(publicSeed, n, "publicSeed");

            Array.Copy(secretKeySeed, 0, m_secretKeySeed, 0, m_secretKeySeed.Length);
            Array.Copy(publicSeed, 0, m_publicSeed, 0, m_publicSeed.Length);
        }

        /// <summary>
        /// Zeroize the WOTS+ secret key imported last. The array cleared is this instance's own, so this reaches
        /// no caller-owned data. The instance is not usable afterwards without a fresh import.
        /// </summary>
        internal void ClearSecretKeySeed() => Arrays.ZeroMemory(m_secretKeySeed);

        /// <summary>Creates a signature for the n-byte messageDigest.</summary>
        /// <param name="messageDigest">Digest to sign.</param>
        /// <param name="address">the 32-byte encoding of the OTS hash address this one-time key is at. The caller
        /// owns it and has set the OTS address word; the loop below writes the chain address word of it and
        /// <see cref="Chain"/> the two after that.</param>
        /// <returns>the len n-byte blocks of the signature, a fresh array of fresh blocks that the caller takes
        /// over.</returns>
        internal byte[][] Sign(byte[] messageDigest, byte[] address)
        {
            List<int> baseWMessage = BaseWMessageWithChecksum(messageDigest);

            /* create signature */
            int n = m_params.TreeDigestSize;
            byte[][] signature = new byte[m_params.Len][];
            // One set of working buffers serves the len chains: every one of them is written before it is read
            // on each chain, and none of them is what Chain returns.
            byte[] indexBuffer = new byte[PrfIndexSize];
            byte[] startHash = new byte[n];
            byte[] key = new byte[n];
            byte[] tmpMasked = new byte[n];
            for (int i = 0; i < m_params.Len; i++)
            {
                Pack.UInt32_To_BE((uint)i, address, XmssAddress.ChainAddressOffset);
                ExpandSecretKeySeed(i, indexBuffer, startHash);
                signature[i] = Chain(startHash, 0, baseWMessage[i], address, key, tmpMasked);
            }
            // tmpMasked holds a secret chain element XORed with a public mask
            Arrays.ZeroMemory(startHash);
            Arrays.ZeroMemory(key);
            Arrays.ZeroMemory(tmpMasked);
            return signature;
        }

        /// <summary>Calculates a public key based on digest and signature.</summary>
        /// <param name="messageDigest">The digest that was signed.</param>
        /// <param name="signature">the len n-byte blocks of the signature on that digest, which this method reads
        /// and never writes.</param>
        /// <param name="address">the 32-byte encoding of the OTS hash address the signing key was at; written as
        /// in <see cref="Sign"/>.</param>
        /// <returns>WOTS+ public key derived from digest and signature.</returns>
        internal WotsPlusPublicKeyParameters GetPublicKeyFromSignature(byte[] messageDigest, byte[][] signature,
            byte[] address)
        {
            List<int> baseWMessage = BaseWMessageWithChecksum(messageDigest);

            // The signature's blocks are chained from where they lie rather than out of a copy of the whole
            // signature; Chain only reads the starting value it is given and returns an array of its own.
            int n = m_params.TreeDigestSize;
            byte[][] publicKey = new byte[m_params.Len][];
            byte[] key = new byte[n];
            byte[] tmpMasked = new byte[n];
            for (int i = 0; i < m_params.Len; i++)
            {
                Pack.UInt32_To_BE((uint)i, address, XmssAddress.ChainAddressOffset);
                publicKey[i] = Chain(signature[i], baseWMessage[i],
                    WotsPlusParameters.WinternitzParameter - 1 - baseWMessage[i], address, key, tmpMasked);
            }
            return new WotsPlusPublicKeyParameters(publicKey);
        }

        /// <summary>Computes an iteration of F on an n-byte input using outputs of PRF.</summary>
        /// <remarks>
        /// <para>
        /// The caller sets the chain address before each call, and the hash address and key-and-mask words are
        /// written at the top of every step, so what a previous chain left in them is overwritten before anything
        /// is hashed. <paramref name="key"/> and <paramref name="tmpMasked"/> are working values: PRF fills all n
        /// bytes of each before it is read.
        /// </para>
        /// <para>
        /// The result is this method's own array, one per call. A zero-step chain copies
        /// <paramref name="startHash"/> into it rather than handing <paramref name="startHash"/> itself back, so a
        /// caller may reuse one startHash buffer across the len chains, and a recovered public key never shares
        /// storage with the signature it came from.
        /// </para>
        /// </remarks>
        /// <param name="startHash">Starting point. Read and never written, and never handed back.</param>
        /// <param name="startIndex">Start index.</param>
        /// <param name="steps">Steps to take.</param>
        /// <param name="address">the 32-byte encoding of this chain's OTS hash address. The caller owns it and has
        /// set the chain address word; this method writes the hash address and key-and-mask words of it.</param>
        /// <param name="key">an n-byte working buffer the caller owns.</param>
        /// <param name="tmpMasked">a second n-byte working buffer on the same terms. It must be neither
        /// <paramref name="key"/> nor <paramref name="startHash"/>.</param>
        /// <returns>a freshly allocated n-byte array holding the value obtained by iterating F for steps times on
        /// input startHash, using the outputs of PRF.</returns>
        private byte[] Chain(byte[] startHash, int startIndex, int steps, byte[] address, byte[] key,
            byte[] tmpMasked)
        {
            int n = m_params.TreeDigestSize;
            if (startHash.Length != n)
                throw new ArgumentException("startHash needs to be " + n + "bytes");
            if ((startIndex + steps) > WotsPlusParameters.WinternitzParameter - 1)
                throw new ArgumentException("max chain length must not be greater than w");

            byte[] output = new byte[n];
            if (steps == 0)
            {
                Array.Copy(startHash, 0, output, 0, n);
                return output;
            }

            byte[] tmp = startHash;
            for (int i = 0; i != steps; i++)
            {
                Pack.UInt32_To_BE((uint)(startIndex + i), address, XmssAddress.HashAddressOffset);

                Pack.UInt32_To_BE(0U, address, XmssAddress.KeyAndMaskOffset);
                m_khf.Prf(m_publicSeed, address, key);

                Pack.UInt32_To_BE(1U, address, XmssAddress.KeyAndMaskOffset);
                m_khf.Prf(m_publicSeed, address, tmpMasked);

                Bytes.XorTo(n, tmp, tmpMasked);
                m_khf.F(key, tmpMasked, output);
                tmp = output;
            }
            return output;
        }

        /// <summary>
        /// The len = len1 + len2 base-w digits WOTS+ signs: the digest's own len1 digits followed by the len2
        /// digits of their checksum (RFC 8391 sec. 3.1.1 algorithm 1, steps 1-3).
        /// </summary>
        private List<int> BaseWMessageWithChecksum(byte[] messageDigest)
        {
            int w = WotsPlusParameters.WinternitzParameter;
            List<int> baseWMessage = ConvertToBaseW(messageDigest, w, m_params.Len1);

            /* create checksum */
            int checksum = 0;
            for (int i = 0; i < m_params.Len1; i++)
            {
                checksum += w - 1 - baseWMessage[i];
            }
            checksum <<= (8 - ((m_params.Len2 * XmssUtilities.Log2(w)) % 8));
            int len2Bytes = (int)System.Math.Ceiling((double)(m_params.Len2 * XmssUtilities.Log2(w)) / 8);
            List<int> baseWChecksum = ConvertToBaseW(XmssUtilities.ToBytesBigEndian(checksum, len2Bytes), w,
                m_params.Len2);

            /* msg || checksum */
            baseWMessage.AddRange(baseWChecksum);

            return baseWMessage;
        }

        /// <summary>Obtain base w values from Input.</summary>
        /// <param name="messageDigest">Input data.</param>
        /// <param name="w">Base.</param>
        /// <param name="outLength">Length of output.</param>
        /// <returns>outLength-length list of base w integers.</returns>
        private static List<int> ConvertToBaseW(byte[] messageDigest, int w, int outLength)
        {
            if (w != 4 && w != 16)
                throw new ArgumentException("w needs to be 4 or 16");

            int logW = XmssUtilities.Log2(w);
            if (outLength > ((8 * messageDigest.Length) / logW))
                throw new ArgumentException("outLength too big");

            List<int> res = new List<int>();
            for (int i = 0; i < messageDigest.Length; i++)
            {
                for (int j = 8 - logW; j >= 0; j -= logW)
                {
                    res.Add((messageDigest[i] >> j) & (w - 1));
                    if (res.Count == outLength)
                        return res;
                }
            }
            return res;
        }

        /// <summary>Derive WOTS+ secret key for specific index as in XMSS ref impl Andreas Huelsing.</summary>
        /// <remarks>
        /// The chain address, hash address and key-and-mask of the caller's encoding are cleared in place before
        /// the PRF, which is what lets one encoding serve a whole leaf walk.
        /// </remarks>
        /// <param name="secretSeed">the XMSS private key's secret seed, SK_SEED of RFC 8391 sec. 4.1.3 - not the
        /// derived seed this instance holds. Every caller hands the result straight to
        /// <see cref="ImportKeys"/>.</param>
        /// <param name="address">the 32-byte encoding of the OTS hash address this one-time key is at.</param>
        /// <returns>WOTS+ secret key at index.</returns>
        internal byte[] GetWotsPlusSecretKey(byte[] secretSeed, byte[] address)
        {
            Pack.UInt32_To_BE(0U, address, XmssAddress.ChainAddressOffset);
            Pack.UInt32_To_BE(0U, address, XmssAddress.HashAddressOffset);
            Pack.UInt32_To_BE(0U, address, XmssAddress.KeyAndMaskOffset);
            return m_khf.Prf(secretSeed, address);
        }

        /// <summary>Derive private key at index from secret key seed.</summary>
        /// <param name="index">Index.</param>
        /// <param name="indexBuffer">a PrfIndexSize-byte buffer the caller owns, which this writes
        /// toByte(index, 32) into. It reaches only the last eight bytes, so one buffer serves every index of a
        /// key.</param>
        /// <param name="output">an n-byte buffer the private key at index is written into.</param>
        private void ExpandSecretKeySeed(int index, byte[] indexBuffer, byte[] output)
        {
            if (index < 0 || index >= m_params.Len)
                throw new ArgumentException("index out of bounds");

            // toByte(index, 32) of RFC 8391 sec. 2.4, written in place
            Pack.UInt64_To_BE_Low((ulong)index, indexBuffer, PrfIndexSize - 8, 8);
            m_khf.Prf(m_secretKeySeed, indexBuffer, output);
        }

        internal WotsPlusParameters Params => m_params;

        internal KeyedHashFunctions Khf => m_khf;

        /// <summary>
        /// This instance's public seed, by reference rather than through a defensive copy. WotsPlus is internal
        /// and the one caller, <see cref="XmssNodeUtilities.RandomizeHash"/>, only passes it to PRF as a key.
        /// </summary>
        internal byte[] PublicSeed => m_publicSeed;

        /// <summary>
        /// Calculates a new public key based on the state of secretKeySeed, publicSeed and the address given.
        /// </summary>
        /// <param name="address">the 32-byte encoding of the OTS hash address this one-time key is at; written as
        /// in <see cref="Sign"/>.</param>
        /// <returns>WOTS+ public key.</returns>
        internal WotsPlusPublicKeyParameters GetPublicKey(byte[] address)
        {
            int n = m_params.TreeDigestSize;
            byte[][] publicKey = new byte[m_params.Len][];
            /* derive public key from secretKeySeed */
            byte[] indexBuffer = new byte[PrfIndexSize];
            byte[] startHash = new byte[n];
            byte[] key = new byte[n];
            byte[] tmpMasked = new byte[n];
            for (int i = 0; i < m_params.Len; i++)
            {
                Pack.UInt32_To_BE((uint)i, address, XmssAddress.ChainAddressOffset);
                ExpandSecretKeySeed(i, indexBuffer, startHash);
                publicKey[i] = Chain(startHash, 0, WotsPlusParameters.WinternitzParameter - 1, address, key,
                    tmpMasked);
            }
            // as in Sign: tmpMasked holds a secret chain element XORed with a public mask
            Arrays.ZeroMemory(startHash);
            Arrays.ZeroMemory(key);
            Arrays.ZeroMemory(tmpMasked);
            return new WotsPlusPublicKeyParameters(publicKey);
        }
    }
}
