using System;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Agreement.Kdf;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Agreement
{
    internal static class BasicAgreementWithKdf
    {
        internal static BigInteger CalculateAgreementWithKdf(AlgorithmIdentifier algID, IDerivationFunction kdf,
            int fieldSize, BigInteger result, byte[] extraInfo)
        {
            // Note that the ec.KeyAgreement class in JCE only uses kdf in one of the engineGenerateSecret methods.

            var algOid = algID.Algorithm;

            int keySize = GeneratorUtilities.GetDefaultKeySize(algOid);
            byte[] z = BigIntegers.AsUnsignedByteArray(fieldSize, result);

            DHKdfParameters kdfParams = new DHKdfParameters(algID, keySize, z, extraInfo);

            kdf.Init(kdfParams);

            int length = keySize / 8;
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<byte> buf = length <= 1024
                ? stackalloc byte[length]
                : new byte[length];
            kdf.GenerateBytes(buf);
#else
            byte[] buf = new byte[length];
            kdf.GenerateBytes(buf, 0, buf.Length);
#endif

            return new BigInteger(1, buf);
        }
    }
}
