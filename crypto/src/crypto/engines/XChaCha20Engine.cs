using System;
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
using System.Runtime.InteropServices;
#endif

using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Engines
{
    /// <summary>
    /// Implementation of Daniel J. Bernstein's XChaCha20 stream cipher - ChaCha20 with an extended nonce.
    /// </summary>
    /// <remarks>
    /// XChaCha20 requires a 256 bit key, and a 192 bit nonce. See
    /// draft-irtf-cfrg-xchacha-03 for the specification.
    /// </remarks>
    public class XChaCha20Engine
        : ChaCha7539Engine
    {
        public override string AlgorithmName => "XChaCha20";

        protected override int NonceSize => 24;

        /// <summary>
        /// XChaCha20 key generation: derive a 256 bit subkey via HChaCha20 from the input key and
        /// the first 128 bits of the input nonce, then initialise a standard ChaCha20 (IETF) state
        /// with that subkey and the remaining 64 bits of nonce (prepended with 32 zero bits).
        /// </summary>
        protected override void SetKey(byte[] keyBytes, byte[] ivBytes)
        {
            if (keyBytes == null)
                throw new ArgumentException(AlgorithmName + " doesn't support re-init with null key");
            if (keyBytes.Length != 32)
                throw new ArgumentException(AlgorithmName + " requires a 256 bit key");

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<byte> subKey = stackalloc byte[32];
            try
            {
                HChaCha20(keyBytes, ivBytes.AsSpan(0, 16), subKey);

                // Standard ChaCha7539 state with the derived subkey and the IETF 96-bit nonce
                // (4 zero bytes || last 8 bytes of the original 192-bit nonce).
                PackTauOrSigma(32, engineState);
                Pack.LE_To_UInt32(subKey, engineState.AsSpan(4, 8));
                engineState[12] = 0U;
                engineState[13] = 0U;
                engineState[14] = Pack.LE_To_UInt32(ivBytes, 16);
                engineState[15] = Pack.LE_To_UInt32(ivBytes, 20);
            }
            finally
            {
                Arrays.ZeroMemory(subKey);
            }
#else
            byte[] subKey = new byte[32];
            try
            {
                HChaCha20(keyBytes, ivBytes, 0, subKey, 0);

                // Standard ChaCha7539 state with the derived subkey and the IETF 96-bit nonce
                // (4 zero bytes || last 8 bytes of the original 192-bit nonce).
                PackTauOrSigma(32, engineState);
                Pack.LE_To_UInt32(subKey, 0, engineState, 4, 8);
                engineState[12] = 0U;
                engineState[13] = 0U;
                engineState[14] = Pack.LE_To_UInt32(ivBytes, 16);
                engineState[15] = Pack.LE_To_UInt32(ivBytes, 20);
            }
            finally
            {
                Arrays.ZeroMemory(subKey);
            }
#endif
        }

        /// <summary>
        /// HChaCha20: the ChaCha20-based key-derivation function used to construct the XChaCha20
        /// subkey. Per draft-irtf-cfrg-xchacha-03 section 2.2, this is 20 rounds of the ChaCha
        /// permutation applied to the standard ChaCha20 state (constants || 256-bit key || 128-bit
        /// nonce), with the final-state addition omitted; the output is the 256-bit concatenation
        /// of state words 0..3 and 12..15.
        /// </summary>
        /// <param name="keyBytes">A 256-bit key.</param>
        /// <param name="nonceBytes">Buffer containing a 128-bit nonce at <paramref name="nonceOff"/>.</param>
        /// <param name="nonceOff">Offset of the nonce in <paramref name="nonceBytes"/>.</param>
        /// <param name="subKeyBytes">Output buffer receiving the 256-bit subkey at <paramref name="subKeyOff"/>.</param>
        /// <param name="subKeyOff">Offset at which to write the subkey.</param>
        internal static void HChaCha20(byte[] keyBytes, byte[] nonceBytes, int nonceOff, byte[] subKeyBytes,
            int subKeyOff)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            HChaCha20(keyBytes.AsSpan(), nonceBytes.AsSpan(nonceOff, 16), subKeyBytes.AsSpan(subKeyOff, 32));
#else
            uint[] state = new uint[16];
            byte[] block = new byte[64];
            try
            {
                PackTauOrSigma(32, state);
                Pack.LE_To_UInt32(keyBytes, 0, state, 4, 8);
                Pack.LE_To_UInt32(nonceBytes, nonceOff, state, 12, 4);

                // ChaChaCore folds the initial state back into its output; subtract it to recover
                // the final-state words at positions 0..3 and 12..15.
                ChaChaEngine.ChaChaCore(20, state, block);

                for (int i = 0; i < 4; ++i)
                {
                    Pack.UInt32_To_LE(Pack.LE_To_UInt32(block,      i * 4) - state[     i],
                        subKeyBytes, subKeyOff      + i * 4);
                    Pack.UInt32_To_LE(Pack.LE_To_UInt32(block, 48 + i * 4) - state[12 + i],
                        subKeyBytes, subKeyOff + 16 + i * 4);
                }
            }
            finally
            {
                Arrays.ZeroMemory(state);
                Arrays.ZeroMemory(block);
            }
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>
        /// Span-based variant of <see cref="HChaCha20(byte[], byte[], int, byte[], int)"/>. Uses
        /// stack-allocated scratch buffers and delegates round computation to the span overload
        /// of <see cref="ChaChaEngine.ChaChaCore(int, ReadOnlySpan{uint}, Span{byte})"/>.
        /// </summary>
        /// <param name="key">A 256-bit key (32 bytes).</param>
        /// <param name="nonce">A 128-bit nonce (16 bytes).</param>
        /// <param name="subKey">Destination for the 256-bit subkey (32 bytes).</param>
        internal static void HChaCha20(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, Span<byte> subKey)
        {
            Span<uint> state = stackalloc uint[16];
            Span<uint> block = stackalloc uint[16];
            try
            {
                PackTauOrSigma(32, state);
                Pack.LE_To_UInt32(key, state.Slice(4, 8));
                Pack.LE_To_UInt32(nonce, state.Slice(12, 4));

                // ChaChaCore feeds the initial state forward into its output; subtract it back
                // out to recover the post-permutation words at positions 0..3 and 12..15.
                Span<byte> blockBytes = MemoryMarshal.AsBytes(block);
                ChaChaEngine.ChaChaCore(20, state, blockBytes);

                for (int i = 0; i < 4; ++i)
                {
                    uint lo, hi;
                    if (BitConverter.IsLittleEndian)
                    {
                        lo = block[     i];
                        hi = block[12 + i];
                    }
                    else
                    {
                        lo = Pack.LE_To_UInt32(blockBytes,      i * 4);
                        hi = Pack.LE_To_UInt32(blockBytes, 48 + i * 4);
                    }

                    Pack.UInt32_To_LE(lo - state[     i], subKey,      i * 4);
                    Pack.UInt32_To_LE(hi - state[12 + i], subKey, 16 + i * 4);
                }
            }
            finally
            {
                Arrays.ZeroMemory(state);
                Arrays.ZeroMemory(block);
            }
        }
#endif
    }
}
