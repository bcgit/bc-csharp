using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Pqc.Crypto.Ntru.Owcpa;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Ntru
{
    /// <summary>
    /// NTRU secret encapsulation extractor.
    /// </summary>
    public class NtruKemExtractor
        : IEncapsulatedSecretExtractor
    {
        private readonly NtruPrivateKeyParameters m_privateKey;

        public NtruKemExtractor(NtruPrivateKeyParameters ntruPrivateKey)
        {
            m_privateKey = ntruPrivateKey ?? throw new ArgumentNullException(nameof(ntruPrivateKey));
        }

        public byte[] ExtractSecret(byte[] encapsulation)
        {
            var parameterSet = m_privateKey.Parameters.ParameterSet;

            if (encapsulation == null)
                throw new ArgumentNullException(nameof(encapsulation));
            if (encapsulation.Length != parameterSet.NtruCiphertextBytes())
                throw new ArgumentException(nameof(encapsulation));

            // TODO[pqc] Avoid copy?
            byte[] sk = m_privateKey.GetEncoded();

            NtruOwcpa owcpa = new NtruOwcpa(parameterSet);
            OwcpaDecryptResult owcpaResult = owcpa.Decrypt(encapsulation, sk);
            byte[] rm = owcpaResult.Rm;
            int fail = owcpaResult.Fail;

            Sha3Digest sha3256 = new Sha3Digest(256);
            byte[] k = new byte[sha3256.GetDigestSize()];

            sha3256.BlockUpdate(rm, 0, rm.Length);
            sha3256.DoFinal(k, 0);

            /* shake(secret PRF key || input ciphertext) */
            sha3256.BlockUpdate(sk, parameterSet.OwcpaSecretKeyBytes(), parameterSet.PrfKeyBytes);
            sha3256.BlockUpdate(encapsulation, 0, encapsulation.Length);
            sha3256.DoFinal(rm, 0);

            Cmov(k, rm, (byte)fail);

            var sharedKey = Arrays.CopyOfRange(k, 0, parameterSet.SharedKeyBytes);
            Array.Clear(k, 0, k.Length);

            return sharedKey;
        }

        private static void Cmov(byte[] r, byte[] x, byte b)
        {
            b = (byte)(~b + 1);
            for (int i = 0; i < r.Length; i++)
            {
                r[i] ^= (byte)(b & (x[i] ^ r[i]));
            }
        }

        public int EncapsulationLength => m_privateKey.Parameters.ParameterSet.NtruCiphertextBytes();
    }
}
