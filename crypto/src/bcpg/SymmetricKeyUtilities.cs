using System;

namespace Org.BouncyCastle.Bcpg
{
    /// <summary>Utility methods for symmetric key algorithms.</summary>
    public static class SymmetricKeyUtilities
    {
        /// <summary>Get the key length of a symmetric key algorithm in bits.</summary>
        /// <param name="symKeyAlgorithm">The algorithm.</param>
        /// <returns>The key length in bits.</returns>
        public static int GetKeyLengthInBits(SymmetricKeyAlgorithmTag symKeyAlgorithm)
        {
            switch (symKeyAlgorithm)
            {
            case SymmetricKeyAlgorithmTag.Null:
                throw new ArgumentException("NULL is no encryption algorithm.", nameof(symKeyAlgorithm));

            case SymmetricKeyAlgorithmTag.Des:
                return 64;

            case SymmetricKeyAlgorithmTag.Idea:
            case SymmetricKeyAlgorithmTag.Cast5:
            case SymmetricKeyAlgorithmTag.Blowfish:
            case SymmetricKeyAlgorithmTag.Safer:
            case SymmetricKeyAlgorithmTag.Aes128:
            case SymmetricKeyAlgorithmTag.Camellia128:
                return 128;

            case SymmetricKeyAlgorithmTag.TripleDes:
            case SymmetricKeyAlgorithmTag.Aes192:
            case SymmetricKeyAlgorithmTag.Camellia192:
                return 192;

            case SymmetricKeyAlgorithmTag.Aes256:
            case SymmetricKeyAlgorithmTag.Twofish:
            case SymmetricKeyAlgorithmTag.Camellia256:
                return 256;

            default:
                throw new ArgumentException("unknown symmetric algorithm: " + symKeyAlgorithm, nameof(symKeyAlgorithm));
            }
        }

        /// <summary>Get the key length of a symmetric key algorithm in bytes.</summary>
        /// <param name="symKeyAlgorithm">The algorithm.</param>
        /// <returns>The key length in bytes.</returns>
        public static int GetKeyLengthInOctets(SymmetricKeyAlgorithmTag symKeyAlgorithm) =>
            (GetKeyLengthInBits(symKeyAlgorithm) + 7) / 8;
    }
}
