using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg.Sig
{
    /// <summary>
    /// Signature Subpacket containing the AEAD ciphersuites (pairs of a symmetric cipher and an AEAD mode) that the
    /// key holder's implementation prefers for version 2 SEIPD packets and version 6 SKESK packets.
    /// </summary>
    /// <remarks>
    /// AES-128 with OCB is always supported, even if it is not listed explicitly.
    /// <para>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9580.html#name-preferred-aead-ciphersuites">
    /// RFC9580 - Preferred AEAD Ciphersuites
    /// </see>
    /// </para>
    /// </remarks>
    public sealed class PreferredAeadCiphersuites
        : PreferredAlgorithms
    {
        /// <summary>A pair of a symmetric cipher and an AEAD mode.</summary>
        public sealed class Combination
        {
            private readonly SymmetricKeyAlgorithmTag m_symmetricAlgorithm;
            private readonly AeadAlgorithmTag m_aeadAlgorithm;

            public Combination(SymmetricKeyAlgorithmTag symmetricAlgorithm, AeadAlgorithmTag aeadAlgorithm)
            {
                m_symmetricAlgorithm = symmetricAlgorithm;
                m_aeadAlgorithm = aeadAlgorithm;
            }

            public SymmetricKeyAlgorithmTag SymmetricAlgorithm => m_symmetricAlgorithm;

            public AeadAlgorithmTag AeadAlgorithm => m_aeadAlgorithm;

            public override bool Equals(object obj)
            {
                return obj is Combination that
                    && this.m_symmetricAlgorithm == that.m_symmetricAlgorithm
                    && this.m_aeadAlgorithm == that.m_aeadAlgorithm;
            }

            public override int GetHashCode() => ((int)m_symmetricAlgorithm << 8) ^ (int)m_aeadAlgorithm;

            public override string ToString() => m_symmetricAlgorithm + "/" + m_aeadAlgorithm;
        }

        private static readonly Combination ImplicitCombination =
            new Combination(SymmetricKeyAlgorithmTag.Aes128, AeadAlgorithmTag.Ocb);

        private static byte[] CombinationsToData(Combination[] combinations)
        {
            if (combinations == null)
                throw new ArgumentNullException(nameof(combinations));

            byte[] data = new byte[2 * combinations.Length];
            for (int i = 0; i < combinations.Length; ++i)
            {
                data[2 * i] = (byte)combinations[i].SymmetricAlgorithm;
                data[2 * i + 1] = (byte)combinations[i].AeadAlgorithm;
            }
            return data;
        }

        private static byte[] CheckData(byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));
            if ((data.Length & 1) != 0)
                throw new ArgumentException("data must consist of pairs of octets", nameof(data));

            return data;
        }

        public PreferredAeadCiphersuites(bool critical, Combination[] combinations)
            : base(SignatureSubpacketTag.PreferredAeadAlgorithms, critical, isLongLength: false,
                CombinationsToData(combinations))
        {
        }

        /// <exception cref="ArgumentException">If the length of <paramref name="data"/> is odd.</exception>
        public PreferredAeadCiphersuites(bool critical, bool isLongLength, byte[] data)
            : base(SignatureSubpacketTag.PreferredAeadAlgorithms, critical, isLongLength, CheckData(data))
        {
        }

        /// <summary>The ciphersuites that are listed explicitly in the subpacket.</summary>
        public Combination[] GetRawAlgorithms()
        {
            byte[] data = Data;

            Combination[] result = new Combination[data.Length / 2];
            for (int i = 0; i < result.Length; ++i)
            {
                result[i] = new Combination((SymmetricKeyAlgorithmTag)data[2 * i], (AeadAlgorithmTag)data[2 * i + 1]);
            }
            return result;
        }

        /// <summary>
        /// The ciphersuites that are explicitly listed, followed by the implicitly supported AES-128 with OCB if it is
        /// not listed.
        /// </summary>
        public Combination[] GetAlgorithms()
        {
            Combination[] raw = GetRawAlgorithms();

            if (Array.IndexOf(raw, ImplicitCombination) >= 0)
                return raw;

            Combination[] result = new Combination[raw.Length + 1];
            Array.Copy(raw, result, raw.Length);
            result[raw.Length] = ImplicitCombination;
            return result;
        }

        /// <summary>Whether the given ciphersuite is supported, explicitly or implicitly.</summary>
        public bool IsSupported(Combination combination)
        {
            if (combination == null)
                throw new ArgumentNullException(nameof(combination));

            return ImplicitCombination.Equals(combination) || Array.IndexOf(GetRawAlgorithms(), combination) >= 0;
        }
    }
}
