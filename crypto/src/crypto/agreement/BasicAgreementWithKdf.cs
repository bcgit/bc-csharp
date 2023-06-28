using System.Security.Cryptography;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto.Agreement.Kdf;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Agreement
{
    internal static class BasicAgreementWithKdf
    {
        internal static BigInteger CalculateAgreementWithKdf(string algorithm, IDerivationFunction kdf, int fieldSize,
            BigInteger result)
        {
            // Note that the ec.KeyAgreement class in JCE only uses kdf in one
            // of the engineGenerateSecret methods.

            int keySize = GeneratorUtilities.GetDefaultKeySize(algorithm);

            DHKdfParameters dhKdfParams = new DHKdfParameters(
                new DerObjectIdentifier(algorithm),
                keySize,
                BigIntegers.AsUnsignedByteArray(fieldSize, result));

            kdf.Init(dhKdfParams);

            byte[] keyBytes = new byte[keySize / 8];
            kdf.GenerateBytes(keyBytes, 0, keyBytes.Length);

            return new BigInteger(1, keyBytes);
        }
    }
}
