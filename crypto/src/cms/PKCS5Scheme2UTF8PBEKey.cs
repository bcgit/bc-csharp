using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;

namespace Org.BouncyCastle.Cms
{
    /// <summary>PKCS#5 scheme 2 PBE key with the password encoded as UTF-8 bytes.</summary>
    public class Pkcs5Scheme2Utf8PbeKey
        : CmsPbeKey
    {
        /// <inheritdoc/>
        public Pkcs5Scheme2Utf8PbeKey(
            char[] password,
            byte[] salt,
            int iterationCount)
            : base(password, salt, iterationCount)
        {
        }

        /// <inheritdoc/>
        public Pkcs5Scheme2Utf8PbeKey(
            char[] password,
            AlgorithmIdentifier keyDerivationAlgorithm)
            : base(password, keyDerivationAlgorithm)
        {
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <inheritdoc/>
        public Pkcs5Scheme2Utf8PbeKey(ReadOnlySpan<char> password, ReadOnlySpan<byte> salt, int iterationCount)
            : base(password, salt, iterationCount)
        {
        }

        /// <inheritdoc/>
        public Pkcs5Scheme2Utf8PbeKey(ReadOnlySpan<char> password, AlgorithmIdentifier keyDerivationAlgorithm)
            : base(password, keyDerivationAlgorithm)
        {
        }
#endif

        internal override KeyParameter GetEncoded(DerObjectIdentifier algorithmOid)
        {
            Pkcs5S2ParametersGenerator gen = new Pkcs5S2ParametersGenerator();

            gen.Init(
                PbeParametersGenerator.Pkcs5PasswordToUtf8Bytes(password),
                salt,
                iterationCount);

            return (KeyParameter) gen.GenerateDerivedParameters(
                algorithmOid.GetID(),
                CmsEnvelopedHelper.GetKeySize(algorithmOid));
        }
    }
}
