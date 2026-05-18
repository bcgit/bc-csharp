using System;

using Org.BouncyCastle.Crypto.Utilities;

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
        public override string AlgorithmName
        {
            get { return "XChaCha20"; }
        }

        protected override int NonceSize
        {
            get { return 24; }
        }

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

            byte[] subKey = new byte[32];
            try
            {
                HChaCha20(keyBytes, ivBytes, 0, subKey, 0);

                // Standard ChaCha7539 state with the derived subkey and the IETF 96-bit nonce
                // (4 zero bytes || last 8 bytes of the original 192-bit nonce).
                PackTauOrSigma(32, engineState, 0);
                Pack.LE_To_UInt32(subKey, 0, engineState, 4, 8);
                engineState[12] = 0U;
                engineState[13] = 0U;
                engineState[14] = Pack.LE_To_UInt32(ivBytes, 16);
                engineState[15] = Pack.LE_To_UInt32(ivBytes, 20);
            }
            finally
            {
                Array.Clear(subKey, 0, subKey.Length);
            }
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
            uint[] state = new uint[16];
            byte[] block = new byte[64];
            try
            {
                Salsa20Engine.PackTauOrSigma(32, state, 0);
                Pack.LE_To_UInt32(keyBytes, 0, state, 4, 8);
                Pack.LE_To_UInt32(nonceBytes, nonceOff, state, 12, 4);

                // ChachaCore folds the initial state back into its output; subtract it to recover
                // the final-state words at positions 0..3 and 12..15.
                ChaChaEngine.ChachaCore(20, state, block);

                uint[] subKey = new uint[8];
                try
                {
                    subKey[0] = Pack.LE_To_UInt32(block,  0) - state[ 0];
                    subKey[1] = Pack.LE_To_UInt32(block,  4) - state[ 1];
                    subKey[2] = Pack.LE_To_UInt32(block,  8) - state[ 2];
                    subKey[3] = Pack.LE_To_UInt32(block, 12) - state[ 3];
                    subKey[4] = Pack.LE_To_UInt32(block, 48) - state[12];
                    subKey[5] = Pack.LE_To_UInt32(block, 52) - state[13];
                    subKey[6] = Pack.LE_To_UInt32(block, 56) - state[14];
                    subKey[7] = Pack.LE_To_UInt32(block, 60) - state[15];

                    Pack.UInt32_To_LE(subKey, 0, 8, subKeyBytes, subKeyOff);
                }
                finally
                {
                    Array.Clear(subKey, 0, subKey.Length);
                }
            }
            finally
            {
                Array.Clear(state, 0, state.Length);
                Array.Clear(block, 0, block.Length);
            }
        }
    }
}
