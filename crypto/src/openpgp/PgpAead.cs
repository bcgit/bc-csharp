using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <summary>Building blocks for the AEAD constructions of RFC 9580 (v2 SEIPD, v6 SKESK, AEAD secret keys).</summary>
    internal static class PgpAead
    {
        /// <summary>The length of the authentication tag of all supported AEAD algorithms, in octets.</summary>
        internal const int TagLength = 16;

        /// <summary>The largest chunk size octet of a v2 SEIPD packet.</summary>
        internal const int MaxChunkSizeOctet = 16;

        /// <summary>Create the block cipher for an AEAD mode; only ciphers with a 128-bit block are supported.</summary>
        internal static IBlockCipher CreateBlockCipher(SymmetricKeyAlgorithmTag symmetricAlgorithm)
        {
            switch (symmetricAlgorithm)
            {
            case SymmetricKeyAlgorithmTag.Aes128:
            case SymmetricKeyAlgorithmTag.Aes192:
            case SymmetricKeyAlgorithmTag.Aes256:
                return AesUtilities.CreateEngine();
            case SymmetricKeyAlgorithmTag.Camellia128:
            case SymmetricKeyAlgorithmTag.Camellia192:
            case SymmetricKeyAlgorithmTag.Camellia256:
                return new CamelliaEngine();
            case SymmetricKeyAlgorithmTag.Twofish:
                return new TwofishEngine();
            default:
                throw new PgpException("unsupported symmetric algorithm for AEAD: " + symmetricAlgorithm);
            }
        }

        /// <summary>Whether the symmetric algorithm can be used with the AEAD modes of OpenPGP.</summary>
        internal static bool IsSupportedCipher(SymmetricKeyAlgorithmTag symmetricAlgorithm)
        {
            switch (symmetricAlgorithm)
            {
            case SymmetricKeyAlgorithmTag.Aes128:
            case SymmetricKeyAlgorithmTag.Aes192:
            case SymmetricKeyAlgorithmTag.Aes256:
            case SymmetricKeyAlgorithmTag.Camellia128:
            case SymmetricKeyAlgorithmTag.Camellia192:
            case SymmetricKeyAlgorithmTag.Camellia256:
            case SymmetricKeyAlgorithmTag.Twofish:
                return true;
            default:
                return false;
            }
        }

        internal static IAeadCipher CreateCipher(SymmetricKeyAlgorithmTag symmetricAlgorithm,
            AeadAlgorithmTag aeadAlgorithm)
        {
            switch (aeadAlgorithm)
            {
            case AeadAlgorithmTag.Eax:
                return new EaxBlockCipher(CreateBlockCipher(symmetricAlgorithm));
            case AeadAlgorithmTag.Ocb:
                return new OcbBlockCipher(CreateBlockCipher(symmetricAlgorithm), CreateBlockCipher(symmetricAlgorithm));
            case AeadAlgorithmTag.Gcm:
                return new GcmBlockCipher(CreateBlockCipher(symmetricAlgorithm));
            default:
                throw new PgpException("unsupported AEAD algorithm: " + aeadAlgorithm);
            }
        }

        /// <summary>HKDF with SHA-256 (RFC 5869).</summary>
        /// <param name="salt">The salt, or null for none.</param>
        internal static byte[] Hkdf(byte[] ikm, byte[] salt, byte[] info, int length) =>
            Hkdf(new Sha256Digest(), ikm, salt, info, length);

        /// <summary>HKDF with the given hash (RFC 5869).</summary>
        /// <param name="salt">The salt, or null for none.</param>
        internal static byte[] Hkdf(IDigest digest, byte[] ikm, byte[] salt, byte[] info, int length)
        {
            var hkdf = new HkdfBytesGenerator(digest);
            hkdf.Init(new HkdfParameters(ikm, salt, info));

            byte[] output = new byte[length];
            hkdf.GenerateBytes(output, 0, length);
            return output;
        }

        /// <summary>The chunk length in octets for a chunk size octet (RFC 9580 5.13.2).</summary>
        internal static int GetChunkLength(int chunkSizeOctet)
        {
            if (chunkSizeOctet < 0 || chunkSizeOctet > MaxChunkSizeOctet)
                throw new ArgumentOutOfRangeException(nameof(chunkSizeOctet));

            return 1 << (chunkSizeOctet + 6);
        }

        /// <summary>
        /// Write the nonce of a chunk: the initialization vector (all but the last 8 octets of the nonce) followed by
        /// the 8-octet big-endian chunk index.
        /// </summary>
        internal static void CreateNonce(byte[] iv, long chunkIndex, byte[] nonce)
        {
            Array.Copy(iv, 0, nonce, 0, iv.Length - 8);
            Pack.UInt64_To_BE((ulong)chunkIndex, nonce, iv.Length - 8);
        }

        /// <summary>
        /// Split the HKDF output of a v2 SEIPD packet into the message key and the initialization vector. The result
        /// array has the key at index 0 and the nonce prefix (zeroed in its last 8 octets) at index 1.
        /// </summary>
        internal static byte[][] DeriveMessageKeyAndIv(SymmetricKeyAlgorithmTag symmetricAlgorithm,
            AeadAlgorithmTag aeadAlgorithm, byte[] sessionKey, byte[] salt, byte[] aad)
        {
            int keyLength = SymmetricKeyUtilities.GetKeyLengthInOctets(symmetricAlgorithm);
            int ivLength = AeadUtilities.GetIVLength(aeadAlgorithm);

            byte[] keyAndIv = Hkdf(sessionKey, salt, aad, keyLength + ivLength - 8);
            try
            {
                return AeadUtilities.SplitMessageKeyAndIv(keyAndIv, symmetricAlgorithm, aeadAlgorithm);
            }
            finally
            {
                Arrays.ZeroMemory(keyAndIv);
            }
        }

        internal static byte[] EncryptOneShot(SymmetricKeyAlgorithmTag symmetricAlgorithm,
            AeadAlgorithmTag aeadAlgorithm, byte[] key, byte[] nonce, byte[] aad, byte[] plaintext)
        {
            IAeadCipher cipher = CreateCipher(symmetricAlgorithm, aeadAlgorithm);
            cipher.Init(true, new AeadParameters(new KeyParameter(key), TagLength * 8, nonce, aad));

            byte[] output = new byte[cipher.GetOutputSize(plaintext.Length)];
            int len = cipher.ProcessBytes(plaintext, 0, plaintext.Length, output, 0);
            len += cipher.DoFinal(output, len);

            return len == output.Length ? output : Arrays.CopyOfRange(output, 0, len);
        }

        /// <exception cref="InvalidCipherTextException">If the authentication tag does not match.</exception>
        internal static byte[] DecryptOneShot(SymmetricKeyAlgorithmTag symmetricAlgorithm,
            AeadAlgorithmTag aeadAlgorithm, byte[] key, byte[] nonce, byte[] aad, byte[] ciphertextAndTag)
        {
            IAeadCipher cipher = CreateCipher(symmetricAlgorithm, aeadAlgorithm);
            cipher.Init(false, new AeadParameters(new KeyParameter(key), TagLength * 8, nonce, aad));

            byte[] output = new byte[cipher.GetOutputSize(ciphertextAndTag.Length)];
            int len = cipher.ProcessBytes(ciphertextAndTag, 0, ciphertextAndTag.Length, output, 0);
            len += cipher.DoFinal(output, len);

            return len == output.Length ? output : Arrays.CopyOfRange(output, 0, len);
        }
    }
}
