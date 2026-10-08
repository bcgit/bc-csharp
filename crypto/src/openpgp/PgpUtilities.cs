using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Threading.Tasks;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.EdEC;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.TeleTrust;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <remarks>Basic utility class.</remarks>
    public sealed class PgpUtilities
    {
        private static readonly S2k LegacyS2k = new S2k(HashAlgorithmTag.MD5);

        private static readonly Dictionary<string, HashAlgorithmTag> NameToHashID = CreateNameToHashID();
        private static readonly Dictionary<DerObjectIdentifier, string> OidToName = CreateOidToName();

        private static Dictionary<string, HashAlgorithmTag> CreateNameToHashID()
        {
            var d = new Dictionary<string, HashAlgorithmTag>(StringComparer.OrdinalIgnoreCase);
            d.Add("sha1", HashAlgorithmTag.Sha1);
            d.Add("sha224", HashAlgorithmTag.Sha224);
            d.Add("sha256", HashAlgorithmTag.Sha256);
            d.Add("sha384", HashAlgorithmTag.Sha384);
            d.Add("sha512", HashAlgorithmTag.Sha512);
            d.Add("ripemd160", HashAlgorithmTag.RipeMD160);
            d.Add("rmd160", HashAlgorithmTag.RipeMD160);
            d.Add("md2", HashAlgorithmTag.MD2);
            d.Add("tiger", HashAlgorithmTag.Tiger192);
            d.Add("haval", HashAlgorithmTag.Haval5pass160);
            d.Add("md5", HashAlgorithmTag.MD5);
            return d;
        }

        private static Dictionary<DerObjectIdentifier, string> CreateOidToName()
        {
            var d = new Dictionary<DerObjectIdentifier, string>();
            d.Add(EdECObjectIdentifiers.id_X25519, "Curve25519");
            d.Add(EdECObjectIdentifiers.id_Ed25519, "Ed25519");
            d.Add(SecObjectIdentifiers.SecP256r1, "NIST P-256");
            d.Add(SecObjectIdentifiers.SecP384r1, "NIST P-384");
            d.Add(SecObjectIdentifiers.SecP521r1, "NIST P-521");
            return d;
        }

        public static MPInteger[] DsaSigToMpi(byte[] encoding)
        {
            try
            {
                Asn1Sequence s = Asn1Sequence.GetInstance(encoding);

                var i1 = DerInteger.GetInstance(s[0]);
                var i2 = DerInteger.GetInstance(s[1]);

                return new MPInteger[]{ new MPInteger(i1.Value), new MPInteger(i2.Value) };
            }
            catch (Exception e)
            {
                throw new PgpException("exception encoding signature", e);
            }
        }

        public static MPInteger[] RsaSigToMpi(byte[] encoding) =>
            new MPInteger[]{ new MPInteger(new BigInteger(1, encoding)) };

        public static string GetDigestName(HashAlgorithmTag hashAlgorithm)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            switch (hashAlgorithm)
            {
            case HashAlgorithmTag.Sha1:
                return "SHA1";
            case HashAlgorithmTag.MD2:
                return "MD2";
            case HashAlgorithmTag.MD5:
                return "MD5";
            case HashAlgorithmTag.RipeMD160:
                return "RIPEMD160";
            case HashAlgorithmTag.Sha224:
                return "SHA224";
            case HashAlgorithmTag.Sha256:
                return "SHA256";
            case HashAlgorithmTag.Sha384:
                return "SHA384";
            case HashAlgorithmTag.Sha512:
                return "SHA512";
            case HashAlgorithmTag.Sha3_256:
            case HashAlgorithmTag.Sha3_256_Old:
                return "SHA3-256";
            case HashAlgorithmTag.Sha3_384:
                return "SHA3-384";
            case HashAlgorithmTag.Sha3_512:
            case HashAlgorithmTag.Sha3_512_Old:
                return "SHA3-512";
            case HashAlgorithmTag.Sha3_224:
                return "SHA3-224";
            case HashAlgorithmTag.Tiger192:
                return "TIGER";
            default:
                throw new PgpException("unknown hash algorithm tag in GetDigestName: " + hashAlgorithm);
            }
#pragma warning restore CS0618 // Type or member is obsolete
        }

        public static int GetDigestIDForName(string name)
        {
            if (NameToHashID.TryGetValue(name, out var hashAlgorithmTag))
                return (int)hashAlgorithmTag;

            throw new ArgumentException("unable to map " + name + " to a hash id", nameof(name));
        }

        /**
         * Return the EC curve name for the passed in OID.
         *
         * @param oid the EC curve object identifier in the PGP key
         * @return  a string representation of the OID.
         */
        public static string GetCurveName(DerObjectIdentifier oid)
        {
            if (OidToName.TryGetValue(oid, out var name))
                return name;

            // fall back
            return ECNamedCurveTable.GetName(oid);
        }

        public static string GetSignatureName(PublicKeyAlgorithmTag keyAlgorithm, HashAlgorithmTag hashAlgorithm)
        {
            string encAlg;
            switch (keyAlgorithm)
            {
            case PublicKeyAlgorithmTag.RsaGeneral:
            case PublicKeyAlgorithmTag.RsaSign:
                encAlg = "RSA";
                break;
            case PublicKeyAlgorithmTag.Dsa:
                encAlg = "DSA";
                break;
            case PublicKeyAlgorithmTag.ECDH:
                encAlg = "ECDH";
                break;
            case PublicKeyAlgorithmTag.ECDsa:
                encAlg = "ECDSA";
                break;
            case PublicKeyAlgorithmTag.EdDsa_Legacy:
                encAlg = "EdDSA";
                break;
            case PublicKeyAlgorithmTag.ElGamalEncrypt: // in some malformed cases.
            case PublicKeyAlgorithmTag.ElGamalGeneral:
                encAlg = "ElGamal";
                break;
            default:
                throw new PgpException("unknown algorithm tag in signature:" + keyAlgorithm);
            }

            return GetDigestName(hashAlgorithm) + "with" + encAlg;
        }

        public static string GetSymmetricCipherName(SymmetricKeyAlgorithmTag algorithm)
        {
            switch (algorithm)
            {
            case SymmetricKeyAlgorithmTag.Null:
                return null;
            case SymmetricKeyAlgorithmTag.TripleDes:
                return "DESEDE";
            case SymmetricKeyAlgorithmTag.Idea:
                return "IDEA";
            case SymmetricKeyAlgorithmTag.Cast5:
                return "CAST5";
            case SymmetricKeyAlgorithmTag.Blowfish:
                return "Blowfish";
            case SymmetricKeyAlgorithmTag.Safer:
                return "SAFER";
            case SymmetricKeyAlgorithmTag.Des:
                return "DES";
            case SymmetricKeyAlgorithmTag.Aes128:
                return "AES";
            case SymmetricKeyAlgorithmTag.Aes192:
                return "AES";
            case SymmetricKeyAlgorithmTag.Aes256:
                return "AES";
            case SymmetricKeyAlgorithmTag.Twofish:
                return "Twofish";
            case SymmetricKeyAlgorithmTag.Camellia128:
                return "Camellia";
            case SymmetricKeyAlgorithmTag.Camellia192:
                return "Camellia";
            case SymmetricKeyAlgorithmTag.Camellia256:
                return "Camellia";
            default:
                throw new PgpException("unknown symmetric algorithm: " + algorithm);
            }
        }

        public static int GetKeySize(SymmetricKeyAlgorithmTag algorithm)
        {
            int keySize;
            switch (algorithm)
            {
            case SymmetricKeyAlgorithmTag.Des:
                keySize = 64;
                break;
            case SymmetricKeyAlgorithmTag.Idea:
            case SymmetricKeyAlgorithmTag.Cast5:
            case SymmetricKeyAlgorithmTag.Blowfish:
            case SymmetricKeyAlgorithmTag.Safer:
            case SymmetricKeyAlgorithmTag.Aes128:
            case SymmetricKeyAlgorithmTag.Camellia128:
                keySize = 128;
                break;
            case SymmetricKeyAlgorithmTag.TripleDes:
            case SymmetricKeyAlgorithmTag.Aes192:
            case SymmetricKeyAlgorithmTag.Camellia192:
                keySize = 192;
                break;
            case SymmetricKeyAlgorithmTag.Aes256:
            case SymmetricKeyAlgorithmTag.Twofish:
            case SymmetricKeyAlgorithmTag.Camellia256:
                keySize = 256;
                break;
            default:
                throw new PgpException("unknown symmetric algorithm: " + algorithm);
            }

            return keySize;
        }

        public static KeyParameter MakeKey(SymmetricKeyAlgorithmTag algorithm, byte[] keyBytes)
        {
            string algName = GetSymmetricCipherName(algorithm);

            return ParameterUtilities.CreateKeyParameter(algName, keyBytes);
        }

        public static KeyParameter MakeRandomKey(SymmetricKeyAlgorithmTag algorithm, SecureRandom random)
        {
            int keySize = GetKeySize(algorithm);
            byte[] keyBytes = new byte[(keySize + 7) / 8];
            random.NextBytes(keyBytes);
            return MakeKey(algorithm, keyBytes);
        }

        internal static byte[] EncodePassPhrase(char[] passPhrase, bool utf8)
        {
            return passPhrase == null
                ? null
                : utf8
                ? Strings.ToUtf8ByteArray(passPhrase)
                : Strings.ToByteArray(passPhrase);
        }

        /// <remarks>
        /// Conversion of the passphrase characters to bytes is performed using Convert.ToByte(), which is
        /// the historical behaviour of the library (1.7 and earlier).
        /// </remarks>
        public static KeyParameter MakeKeyFromPassPhrase(SymmetricKeyAlgorithmTag algorithm, S2k s2k, char[] passPhrase)
        {
            return DoMakeKeyFromPassPhrase(algorithm, s2k, EncodePassPhrase(passPhrase, false), true);
        }

        /// <remarks>
        /// The passphrase is encoded to bytes using UTF8.
        /// </remarks>
        public static KeyParameter MakeKeyFromPassPhraseUtf8(SymmetricKeyAlgorithmTag algorithm, S2k s2k,
            char[] passPhrase)
        {
            return DoMakeKeyFromPassPhrase(algorithm, s2k, EncodePassPhrase(passPhrase, true), true);
        }

        /// <remarks>
        /// Allows the caller to handle the encoding of the passphrase to bytes.
        /// </remarks>
        public static KeyParameter MakeKeyFromPassPhraseRaw(SymmetricKeyAlgorithmTag algorithm, S2k s2k,
            byte[] rawPassPhrase)
        {
            return DoMakeKeyFromPassPhrase(algorithm, s2k, rawPassPhrase, false);
        }

        internal static KeyParameter DoMakeKeyFromPassPhrase(SymmetricKeyAlgorithmTag algorithm, S2k s2k,
            byte[] rawPassPhrase, bool clearPassPhrase)
        {
            try
            {
                return ImplMakeKeyFromPassPhrase(algorithm, s2k, rawPassPhrase, clearPassPhrase);
            }
            finally
            {
                if (clearPassPhrase && rawPassPhrase != null)
                {
                    Arrays.ZeroMemory(rawPassPhrase);
                }
            }
        }

        private static KeyParameter ImplMakeKeyFromPassPhrase(SymmetricKeyAlgorithmTag algorithm, S2k s2k,
            byte[] rawPassPhrase, bool clearPassPhrase)
        {
            int keySize = GetKeySize(algorithm);
            byte[] pBytes = rawPassPhrase;
            byte[] keyBytes = new byte[(keySize + 7) / 8];

            if (s2k == null)
            {
                s2k = LegacyS2k;
            }

            if (S2k.Argon2 == s2k.Type)
            {
                var argon2Config = s2k.Argon2Config;

                // The passes, parallelism and memory-size fields are one-byte values taken verbatim from
                // the (unauthenticated) S2K packet, and Argon2 must run before the message can be
                // authenticated. Clamp all three to conservative, property-overridable maxima so a single
                // decrypt attempt cannot be driven into a huge allocation or unbounded CPU work. The clamp
                // stays here (above the backend) so any operators/calculators cannot diverge on it.
                // RFC 9580 sec. 3.7.1.4 + RFC 9106 sec. 3.1: memory size m = 2^memorySizeExponent
                // KiB must satisfy m >= 8*p, i.e. memorySizeExponent >= 3 + ceil(log2(p)).
                // For p >= 1 this is 3 + bitLen(p - 1).
                // The limits are read before the packet values are checked, so that a misconfigured property is
                // reported whatever the packet contains.
                // TODO[pgp] In principle these checks could be left to the untrusted Argon2Parameters.Builder below,
                // which applies the same limits (and RFC 9106's minimum memory, in Build()), wrapping its exceptions
                // in PgpException.

                int maxParallelism = GetArgon2Limit(Properties.Argon2MaxParallelism, 16, 1, 255);
                int maxMemorySizeExponent = GetArgon2Limit(Properties.Argon2MaxMemoryExp, 24, 3, 30);
                int maxPasses = GetArgon2Limit(Properties.Argon2MaxPasses, 10, 1, 255);

                int parallelism = argon2Config.Parallelism;
                if (parallelism < 1 || parallelism > maxParallelism)
                    throw new PgpException("parallelism out of range");

                int memorySizeExponent = argon2Config.MemorySizeExponent;
                if (memorySizeExponent < 3 + Integers.BitLength(parallelism - 1) ||
                    memorySizeExponent > maxMemorySizeExponent)
                {
                    throw new PgpException("memory size exponent out of range");
                }

                int passes = argon2Config.Passes;
                if (passes < 1 || passes > maxPasses)
                    throw new PgpException("passes out of range");

                // In 'trusted' mode since we applied our own checks.
                var argon2Parameters = new Argon2Parameters.Builder(Argon2Parameters.Argon2id)
                    .WithSalt(argon2Config.GetSalt())
                    .WithIterations(argon2Config.Passes)
                    .WithParallelism(argon2Config.Parallelism)
                    .WithMemoryPowOfTwo(argon2Config.MemorySizeExponent)
                    .WithVersion(Argon2Parameters.Version13)
                    .Build();

                // TODO Consider ways to customize how Argon2 generation is done
                Argon2BytesGenerator argon2 = new Argon2BytesGenerator(Task.Factory);
                argon2.Init(argon2Parameters);
                argon2.GenerateBytes(rawPassPhrase, keyBytes);

                return MakeKey(algorithm, keyBytes);
            }

            IDigest digest;
            try
            {
                digest = CreateDigest(s2k.HashAlgorithm);
            }
            catch (Exception e)
            {
                throw new PgpException($"can't create {GetDigestName(s2k.HashAlgorithm)} digest", e);
            }

            int generatedBytes = 0, loopCount = 0;

            while (generatedBytes < keyBytes.Length)
            {
                for (int i = 0; i < loopCount; ++i)
                {
                    digest.Update(0);
                }

                switch (s2k.Type)
                {
                case S2k.Simple:
                {
                    digest.BlockUpdate(pBytes, 0, pBytes.Length);
                    break;
                }
                case S2k.Salted:
                {
                    byte[] iv = s2k.GetIV();
                    digest.BlockUpdate(iv, 0, iv.Length);
                    digest.BlockUpdate(pBytes, 0, pBytes.Length);
                    break;
                }
                case S2k.SaltedAndIterated:
                {
                    byte[] iv = s2k.GetIV();
                    digest.BlockUpdate(iv, 0, iv.Length);
                    digest.BlockUpdate(pBytes, 0, pBytes.Length);

                    long count = s2k.IterationCount - iv.Length - pBytes.Length;
                    while (count > 0)
                    {
                        if (count <= iv.Length)
                        {
                            digest.BlockUpdate(iv, 0, (int)count);
                            break;
                        }

                        digest.BlockUpdate(iv, 0, iv.Length);
                        count -= iv.Length;

                        if (count <= pBytes.Length)
                        {
                            digest.BlockUpdate(pBytes, 0, (int)count);
                            break;
                        }

                        digest.BlockUpdate(pBytes, 0, pBytes.Length);
                        count -= pBytes.Length;
                    }
                    break;
                }
                default:
                    throw new PgpException("unknown S2k type: " + s2k.Type);
                }

                byte[] dig = DigestUtilities.DoFinal(digest);
                int toCopy = System.Math.Min(dig.Length, keyBytes.Length - generatedBytes);
                Array.Copy(dig, 0, keyBytes, generatedBytes, toCopy);
                generatedBytes += toCopy;

                loopCount++;
            }

            return MakeKey(algorithm, keyBytes);
        }

        // A limit below minValue would reject every Argon2 S2K, so it is reported as a configuration error. A limit
        // above maxValue (the most an S2K can specify, or Argon2Parameters accept) is no limit, so it is clamped.
        private static int GetArgon2Limit(string propertyName, int defaultValue, int minValue, int maxValue)
        {
            int limit = Properties.GetInt32(propertyName, defaultValue);
            if (limit < minValue)
                throw new InvalidOperationException($"{propertyName} out of range");

            return System.Math.Min(limit, maxValue);
        }

        /// <summary>Write out the passed in file as a literal data packet.</summary>
        public static void WriteFileToLiteralData(Stream output, char fileType, FileInfo file)
        {
            PgpLiteralDataGenerator lData = new PgpLiteralDataGenerator();
            using (var pOut = lData.Open(output, fileType, file.Name, file.Length, file.LastWriteTime))
            {
                PipeFileContents(file, pOut);
            }
        }

        /// <summary>Write out the passed in file as a literal data packet in partial packet format.</summary>
        public static void WriteFileToLiteralData(Stream output, char fileType, FileInfo file, byte[] buffer)
        {
            PgpLiteralDataGenerator lData = new PgpLiteralDataGenerator();
            using (var pOut = lData.Open(output, fileType, file.Name, file.LastWriteTime, buffer))
            {
                PipeFileContents(file, pOut, buffer.Length);
            }
        }

        private static void PipeFileContents(FileInfo file, Stream pOut) =>
            PipeFileContents(file, pOut, Streams.DefaultBufferSize);

        private static void PipeFileContents(FileInfo file, Stream pOut, int bufferSize)
        {
            using (var fileStream = file.OpenRead())
            {
                Streams.CopyTo(fileStream, pOut, bufferSize);
            }
        }

        private const int ReadAhead = 60;

        private static bool IsPossiblyBase64(int ch)
        {
            return (ch >= 'A' && ch <= 'Z')
                || (ch >= 'a' && ch <= 'z')
                || (ch >= '0' && ch <= '9')
                || (ch == '+')
                || (ch == '/')
                || (ch == '\r')
                || (ch == '\n');
        }

        /// <summary>
        /// Return either an ArmoredInputStream or a BcpgInputStream based on whether
        /// the initial characters of the stream are binary PGP encodings or not.
        /// </summary>
        public static Stream GetDecoderStream(Stream inputStream)
        {
            // TODO Remove this restriction?
            if (!inputStream.CanSeek)
                throw new ArgumentException("inputStream must be seek-able", nameof(inputStream));

            long markedPos = inputStream.Position;

            int ch = inputStream.ReadByte();
            if ((ch & 0x80) != 0)
                return AtPosition(inputStream, markedPos);

            if (!IsPossiblyBase64(ch))
                return new ArmoredInputStream(AtPosition(inputStream, markedPos));

            byte[] buf = new byte[ReadAhead];
            int count = 0;
            int index = 1;

            buf[0] = (byte)ch;
            while (++count != ReadAhead && (ch = inputStream.ReadByte()) >= 0)
            {
                if (!IsPossiblyBase64(ch))
                    return new ArmoredInputStream(AtPosition(inputStream, markedPos));

                if (ch != '\n' && ch != '\r')
                {
                    buf[index++] = (byte)ch;
                }
            }

            inputStream.Position = markedPos;

            //
            // nothing but new lines, little else, assume regular armoring
            //
            if (index < 4)
                return new ArmoredInputStream(inputStream);

            //
            // test our non-blank data
            //
            Debug.Assert(buf.Length >= 8);

            try
            {
                byte[] decoded = Base64.Decode(buf, 0, 8);

                //
                // it's a base64 PGP block.
                //
                bool hasHeaders = (decoded[0] & 0x80) == 0;

                return new ArmoredInputStream(inputStream, hasHeaders);
            }
            catch (IOException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new IOException(e.Message);
            }
        }

        internal static IDigest CreateDigest(HashAlgorithmTag hashAlgorithm) =>
            DigestUtilities.GetDigest(GetDigestName(hashAlgorithm));

        internal static ISigner CreateSigner(PublicKeyAlgorithmTag publicKeyAlgorithm, HashAlgorithmTag hashAlgorithm,
            AsymmetricKeyParameter key)
        {
            switch (publicKeyAlgorithm)
            {
            case PublicKeyAlgorithmTag.EdDsa_Legacy:
            case PublicKeyAlgorithmTag.Ed25519:
            case PublicKeyAlgorithmTag.Ed448:
            {
                ISigner signer;
                if (key is Ed25519PrivateKeyParameters || key is Ed25519PublicKeyParameters)
                {
                    signer = new Ed25519Signer();
                }
                else if (key is Ed448PrivateKeyParameters || key is Ed448PublicKeyParameters)
                {
                    signer = new Ed448Signer(Arrays.EmptyBytes);
                }
                else
                {
                    throw new InvalidOperationException();
                }

                return new PgpDigestSigner(signer, CreateDigest(hashAlgorithm));
            }
            case PublicKeyAlgorithmTag.MLDsa65_Ed25519:
            case PublicKeyAlgorithmTag.MLDsa87_Ed448:
                return new PgpDigestSigner(new PgpCompositeSigner(publicKeyAlgorithm), CreateDigest(hashAlgorithm));
            case PublicKeyAlgorithmTag.SlhDsa_Shake128s:
            case PublicKeyAlgorithmTag.SlhDsa_Shake128f:
            case PublicKeyAlgorithmTag.SlhDsa_Shake256s:
                return new PgpDigestSigner(
                    new SlhDsaSigner(GetSlhDsaParameters(publicKeyAlgorithm), deterministic: false),
                    CreateDigest(hashAlgorithm));
            default:
            {
                try
                {
                    return SignerUtilities.GetSigner(GetSignatureName(publicKeyAlgorithm, hashAlgorithm));
                }
                catch (SecurityUtilityException e)
                {
                    throw new PgpException("cannot use " + publicKeyAlgorithm + " for signatures", e);
                }
            }
            }
        }

        /// <summary>
        /// As <see cref="IsHashStrongEnough(PublicKeyAlgorithmTag, HashAlgorithmTag)"/> for the given key: an
        /// EdDSALegacy key over Ed448 needs the 57 octets of the fsize of its curve (RFC 9580 5.2.3.3), that is 512
        /// bits.
        /// </summary>
        internal static bool IsHashStrongEnough(PublicKeyAlgorithmTag keyAlgorithm, HashAlgorithmTag hashAlgorithm,
            AsymmetricKeyParameter key)
        {
            if (keyAlgorithm == PublicKeyAlgorithmTag.EdDsa_Legacy &&
                (key is Ed448PublicKeyParameters || key is Ed448PrivateKeyParameters))
            {
                return IsHashStrongEnough(PublicKeyAlgorithmTag.Ed448, hashAlgorithm);
            }

            return IsHashStrongEnough(keyAlgorithm, hashAlgorithm);
        }

        /// <summary>
        /// The hash algorithm for the signatures of the given keys where the caller names none: SHA-256, or a larger
        /// one where RFC 9580 5.2.3.2-5 requires it, for ECDSA and DSA over larger groups and for Ed448.
        /// </summary>
        internal static HashAlgorithmTag GetDefaultHashAlgorithm(params PgpPublicKey[] signingKeys)
        {
            int minDigestBits = 256;
            foreach (PgpPublicKey key in signingKeys)
            {
                minDigestBits = System.Math.Max(minDigestBits, GetMinimumDigestBits(key));
            }

            if (minDigestBits <= 256)
                return HashAlgorithmTag.Sha256;
            if (minDigestBits <= 384)
                return HashAlgorithmTag.Sha384;

            return HashAlgorithmTag.Sha512;
        }

        private static int GetMinimumDigestBits(PgpPublicKey key)
        {
            IBcpgKey bcpgKey = key.PublicKeyPacket.Key;
            switch (key.Algorithm)
            {
            case PublicKeyAlgorithmTag.ECDsa:
            {
                // RFC 9580 5.2.3.2: the fsize of the curve, but 512 bits for NIST P-521
                X9ECParameters curve = bcpgKey is ECPublicBcpgKey ecKey
                    ? ECNamedCurveTable.GetByOid(ecKey.CurveOid)
                    : null;
                return curve == null ? 0 : System.Math.Min((curve.Curve.FieldSize + 7) / 8 * 8, 512);
            }
            case PublicKeyAlgorithmTag.Dsa:
                // RFC 9580 5.2.3.2: the size of q
                return bcpgKey is DsaPublicBcpgKey dsaKey ? dsaKey.Q.BitLength : 0;
            case PublicKeyAlgorithmTag.EdDsa_Legacy:
                // RFC 9580 5.2.3.3: the fsize of Ed448 is 57 octets
                return bcpgKey is EdDsaPublicBcpgKey edKey && EdECObjectIdentifiers.id_Ed448.Equals(edKey.CurveOid)
                    ? 512
                    : 256;
            case PublicKeyAlgorithmTag.Ed448:
                return 512;
            default:
                return 0;
            }
        }

        /// <summary>
        /// Check the minimum digest size for signatures of the given key algorithm: 256 bits for EdDSALegacy and
        /// Ed25519 and 512 bits for Ed448 (RFC 9580 5.2.3.3-5). Other algorithms are not restricted here.
        /// </summary>
        internal static bool IsHashStrongEnough(PublicKeyAlgorithmTag keyAlgorithm, HashAlgorithmTag hashAlgorithm)
        {
            int minDigestBits;
            switch (keyAlgorithm)
            {
            case PublicKeyAlgorithmTag.EdDsa_Legacy:
            case PublicKeyAlgorithmTag.Ed25519:
            case PublicKeyAlgorithmTag.MLDsa65_Ed25519:
            case PublicKeyAlgorithmTag.MLDsa87_Ed448:
            case PublicKeyAlgorithmTag.SlhDsa_Shake128s:
            case PublicKeyAlgorithmTag.SlhDsa_Shake128f:
            case PublicKeyAlgorithmTag.SlhDsa_Shake256s:
                minDigestBits = 256;
                break;
            case PublicKeyAlgorithmTag.Ed448:
                minDigestBits = 512;
                break;
            default:
                return true;
            }

            IDigest digest;
            try
            {
                digest = CreateDigest(hashAlgorithm);
            }
            catch (Exception)
            {
                return false;
            }

            return digest.GetDigestSize() * 8 >= minDigestBits;
        }

        /// <summary>
        /// The KDF hash and KEK algorithm that RFC 9580 9.2 (table of ECDH KDF and KEK parameters) prescribes for
        /// version 6 ECDH keys over the given curve.
        /// </summary>
        /// <returns>The parameters, or null for a curve that has none.</returns>
        internal static PgpKdfParameters GetMandatedEcdhKdfParameters(DerObjectIdentifier curveOid)
        {
            if (SecObjectIdentifiers.SecP256r1.Equals(curveOid) ||
                TeleTrusTObjectIdentifiers.BrainpoolP256R1.Equals(curveOid))
            {
                return new PgpKdfParameters(HashAlgorithmTag.Sha256, SymmetricKeyAlgorithmTag.Aes128);
            }
            if (SecObjectIdentifiers.SecP384r1.Equals(curveOid) ||
                TeleTrusTObjectIdentifiers.BrainpoolP384R1.Equals(curveOid))
            {
                return new PgpKdfParameters(HashAlgorithmTag.Sha384, SymmetricKeyAlgorithmTag.Aes192);
            }
            if (SecObjectIdentifiers.SecP521r1.Equals(curveOid) ||
                TeleTrusTObjectIdentifiers.BrainpoolP512R1.Equals(curveOid))
            {
                return new PgpKdfParameters(HashAlgorithmTag.Sha512, SymmetricKeyAlgorithmTag.Aes256);
            }

            return null;
        }

        /// <summary>The salt size in octets of a version 6 signature made with the hash, or -1 if there is none.</summary>
        /// <remarks>RFC 9580 9.5 (table of hash algorithms): only these hashes can be used for version 6 signatures.</remarks>
        internal static int GetV6SaltSize(HashAlgorithmTag hashAlgorithm)
        {
            switch (hashAlgorithm)
            {
            case HashAlgorithmTag.Sha256:
            case HashAlgorithmTag.Sha224:
            case HashAlgorithmTag.Sha3_256:
                return 16;
            case HashAlgorithmTag.Sha384:
                return 24;
            case HashAlgorithmTag.Sha512:
            case HashAlgorithmTag.Sha3_512:
                return 32;
            default:
                return -1;
            }
        }

        /// <summary>Whether a signature of the given algorithm can be made or verified by a key of the other.</summary>
        internal static bool IsSignatureAlgorithmCompatible(PublicKeyAlgorithmTag signatureAlgorithm,
            PublicKeyAlgorithmTag keyAlgorithm)
        {
            if (signatureAlgorithm == keyAlgorithm)
                return true;

            return IsRsaSigningAlgorithm(signatureAlgorithm) && IsRsaSigningAlgorithm(keyAlgorithm);
        }

        private static bool IsRsaSigningAlgorithm(PublicKeyAlgorithmTag algorithm)
        {
            return algorithm == PublicKeyAlgorithmTag.RsaGeneral || algorithm == PublicKeyAlgorithmTag.RsaSign;
        }

        /// <summary>The SLH-DSA algorithms (32 to 34).</summary>
        internal static bool IsSlhDsaAlgorithm(PublicKeyAlgorithmTag algorithm)
        {
            switch (algorithm)
            {
            case PublicKeyAlgorithmTag.SlhDsa_Shake128s:
            case PublicKeyAlgorithmTag.SlhDsa_Shake128f:
            case PublicKeyAlgorithmTag.SlhDsa_Shake256s:
                return true;
            default:
                return false;
            }
        }

        /// <summary>The SLH-DSA parameter set of an OpenPGP algorithm (RFC 9980 6.1).</summary>
        internal static SlhDsaParameters GetSlhDsaParameters(PublicKeyAlgorithmTag algorithm)
        {
            switch (algorithm)
            {
            case PublicKeyAlgorithmTag.SlhDsa_Shake128s: return SlhDsaParameters.slh_dsa_shake_128s;
            case PublicKeyAlgorithmTag.SlhDsa_Shake128f: return SlhDsaParameters.slh_dsa_shake_128f;
            case PublicKeyAlgorithmTag.SlhDsa_Shake256s: return SlhDsaParameters.slh_dsa_shake_256s;
            default: throw new ArgumentException("not an SLH-DSA algorithm", nameof(algorithm));
            }
        }

        /// <summary>The composite ML-KEM algorithms (35 and 36), which can only encrypt.</summary>
        internal static bool IsCompositeKemAlgorithm(PublicKeyAlgorithmTag algorithm) =>
            algorithm == PublicKeyAlgorithmTag.MLKem768_X25519 || algorithm == PublicKeyAlgorithmTag.MLKem1024_X448;

        /// <summary>The algorithms that can make signatures (excluding ElGamal, which only encrypts).</summary>
        internal static bool IsSigningAlgorithm(PublicKeyAlgorithmTag algorithm)
        {
            switch (algorithm)
            {
            case PublicKeyAlgorithmTag.RsaGeneral:
            case PublicKeyAlgorithmTag.RsaSign:
            case PublicKeyAlgorithmTag.Dsa:
            case PublicKeyAlgorithmTag.ECDsa:
            case PublicKeyAlgorithmTag.EdDsa_Legacy:
            case PublicKeyAlgorithmTag.Ed25519:
            case PublicKeyAlgorithmTag.Ed448:
            case PublicKeyAlgorithmTag.MLDsa65_Ed25519:
            case PublicKeyAlgorithmTag.MLDsa87_Ed448:
            case PublicKeyAlgorithmTag.SlhDsa_Shake128s:
            case PublicKeyAlgorithmTag.SlhDsa_Shake128f:
            case PublicKeyAlgorithmTag.SlhDsa_Shake256s:
                return true;
            default:
                return false;
            }
        }

        /// <summary>Whether the algorithm is one of those introduced by RFC 9980 (30 to 36).</summary>
        internal static bool IsRfc9980Algorithm(PublicKeyAlgorithmTag algorithm)
        {
            switch (algorithm)
            {
            case PublicKeyAlgorithmTag.MLDsa65_Ed25519:
            case PublicKeyAlgorithmTag.MLDsa87_Ed448:
            case PublicKeyAlgorithmTag.SlhDsa_Shake128s:
            case PublicKeyAlgorithmTag.SlhDsa_Shake128f:
            case PublicKeyAlgorithmTag.SlhDsa_Shake256s:
            case PublicKeyAlgorithmTag.MLKem768_X25519:
            case PublicKeyAlgorithmTag.MLKem1024_X448:
                return true;
            default:
                return false;
            }
        }

        /// <summary>
        /// Hash algorithms that must not be used in the S2K specifier of version 6 packets (RFC 9580 9.5).
        /// </summary>
        internal static bool IsWeakS2kHash(HashAlgorithmTag hashAlgorithm) => IsWeakBindingHash(hashAlgorithm);

        /// <summary>The ciphers that RFC 9580 9.3 only allows to decrypt with: IDEA, TripleDES and CAST5.</summary>
        internal static bool IsDecryptOnlyCipher(SymmetricKeyAlgorithmTag cipher) =>
            cipher == SymmetricKeyAlgorithmTag.Idea ||
            cipher == SymmetricKeyAlgorithmTag.TripleDes ||
            cipher == SymmetricKeyAlgorithmTag.Cast5;

        /// <summary>
        /// Hash algorithms that must not be used for subkey binding signatures over RFC 9980 keys (RFC 9980 7.2), nor
        /// for any new signature (RFC 9580 9.5).
        /// </summary>
        internal static bool IsWeakBindingHash(HashAlgorithmTag hashAlgorithm)
        {
            switch (hashAlgorithm)
            {
            case HashAlgorithmTag.MD2:
            case HashAlgorithmTag.MD5:
            case HashAlgorithmTag.Sha1:
            case HashAlgorithmTag.RipeMD160:
                return true;
            default:
                return false;
            }
        }

        internal static IWrapper CreateWrapper(SymmetricKeyAlgorithmTag encAlgorithm)
        {
            switch (encAlgorithm)
            {
            case SymmetricKeyAlgorithmTag.Aes128:
            case SymmetricKeyAlgorithmTag.Aes192:
            case SymmetricKeyAlgorithmTag.Aes256:
                return WrapperUtilities.GetWrapper("AESWRAP");
            case SymmetricKeyAlgorithmTag.Camellia128:
            case SymmetricKeyAlgorithmTag.Camellia192:
            case SymmetricKeyAlgorithmTag.Camellia256:
                return WrapperUtilities.GetWrapper("CAMELLIAWRAP");
            default:
                throw new PgpException("unknown wrap algorithm: " + encAlgorithm);
            }
        }

        private static Stream AtPosition(Stream stream, long position)
        {
            stream.Position = position;
            return stream;
        }
    }
}
