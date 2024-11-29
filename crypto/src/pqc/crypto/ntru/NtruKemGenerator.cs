using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Pqc.Crypto.Ntru.Owcpa;
using Org.BouncyCastle.Pqc.Crypto.Ntru.Polynomials;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Ntru
{
    /// <summary>
    /// Encapsulate a secret using NTRU. Returns an <see cref="NtruEncapsulation"/> as encapsulation.
    /// </summary>
    ///
    /// <seealso cref="NtruKemExtractor"/>
    /// <seealso href="https://ntru.org/">NTRU website</seealso>
    public class NtruKemGenerator
        : IEncapsulatedSecretGenerator
    {
        private readonly SecureRandom m_random;

        public NtruKemGenerator(SecureRandom random)
        {
            m_random = random ?? throw new ArgumentNullException(nameof(random));
        }

        public ISecretWithEncapsulation GenerateEncapsulated(AsymmetricKeyParameter recipientKey)
        {
            if (recipientKey == null)
                throw new ArgumentNullException(nameof(recipientKey));
            if (!(recipientKey is NtruPublicKeyParameters publicKey))
                throw new ArgumentException(nameof(recipientKey));

            var parameterSet = publicKey.Parameters.ParameterSet;
            var sampling = new NtruSampling(parameterSet);
            var owcpa = new NtruOwcpa(parameterSet);
            var rm = new byte[parameterSet.OwcpaMsgBytes()];
            var rmSeed = new byte[parameterSet.SampleRmBytes()];

            m_random.NextBytes(rmSeed);

            var pair = sampling.SampleRm(rmSeed);
            Polynomial r = pair.R();
            Polynomial m = pair.M();

            r.S3ToBytes(rm, 0);
            m.S3ToBytes(rm, parameterSet.PackTrinaryBytes());

            var sha3256 = new Sha3Digest(256);
            var k = new byte[sha3256.GetDigestSize()];

            sha3256.BlockUpdate(rm, 0, rm.Length);
            sha3256.DoFinal(k, 0);

            r.Z3ToZq();

            // TODO[pqc] Avoid copy?
            var c = owcpa.Encrypt(r, m, publicKey.GetEncoded());

            var sharedKey = Arrays.CopyOfRange(k, 0, parameterSet.SharedKeyBytes);
            Array.Clear(k, 0, k.Length);

            return new NtruEncapsulation(sharedKey, c);
        }
    }
}
