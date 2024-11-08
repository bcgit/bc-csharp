using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Pqc.Crypto.Ntru.Owcpa;
using Org.BouncyCastle.Pqc.Crypto.Ntru.Polynomials;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Pqc.Crypto.Ntru
{
    /// <summary>
    /// Encapsulate a secret using NTRU. Returns an <see cref="NtruEncapsulation"/> as encapsulation.
    /// </summary>
    ///
    /// <seealso cref="NtruKemExtractor"/>
    /// <seealso href="https://ntru.org/">NTRU website</seealso>
    public class NtruKemGenerator : IEncapsulatedSecretGenerator
    {
        private readonly SecureRandom _random;

        public NtruKemGenerator(SecureRandom random)
        {
            _random = random;
        }

        public ISecretWithEncapsulation GenerateEncapsulated(AsymmetricKeyParameter recipientKey)
        {
            var parameterSet = ((NtruPublicKeyParameters)recipientKey).Parameters.ParameterSet;
            var sampling = new NtruSampling(parameterSet);
            var owcpa = new NtruOwcpa(parameterSet);
            var rm = new byte[parameterSet.OwcpaMsgBytes()];
            var rmSeed = new byte[parameterSet.SampleRmBytes()];

            _random.NextBytes(rmSeed);

            var pair = sampling.SampleRm(rmSeed);
            Polynomial r = pair.R();
            Polynomial m = pair.M();

            r.S3ToBytes(rm, 0);
            m.S3ToBytes(rm, parameterSet.PackTrinaryBytes());

            var sha3256 = new Sha3Digest(256);
            sha3256.BlockUpdate(rm, 0, rm.Length);


            var k = new byte[sha3256.GetDigestSize()];

            sha3256.DoFinal(k, 0);


            r.Z3ToZq();

            var c = owcpa.Encrypt(r, m, ((NtruPublicKeyParameters)recipientKey).PublicKey);

            var sharedKey = new byte[parameterSet.SharedKeyBytes];
            Array.Copy(k, 0, sharedKey, 0, sharedKey.Length);

            Array.Clear(k, 0, k.Length);

            return new NtruEncapsulation(sharedKey, c);
        }
    }
}