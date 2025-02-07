using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.Utilities.Date;
using Org.BouncyCastle.Utilities.IO;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Security
{
    public class JksStore
    {
        private static readonly int Magic = unchecked((int)0xFEEDFEED);

        private static readonly AlgorithmIdentifier JksObfuscationAlg = new AlgorithmIdentifier(
            new DerObjectIdentifier("1.3.6.1.4.1.42.2.17.1.1"), DerNull.Instance);

        private readonly Dictionary<string, JksTrustedCertEntry> m_certificateEntries =
            new Dictionary<string, JksTrustedCertEntry>(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, JksKeyEntry> m_keyEntries =
            new Dictionary<string, JksKeyEntry>(StringComparer.OrdinalIgnoreCase);

        public JksStore()
        {
        }

        /// <exception cref="IOException"/>
        public bool Probe(Stream stream)
        {
            using (var br = new BinaryReader(stream))
            try
            {
                return Magic == BinaryReaders.ReadInt32BigEndian(br);
            }
            catch (EndOfStreamException)
            {
                return false;
            }
        }

        /// <exception cref="IOException"/>
        public AsymmetricKeyParameter GetKey(string alias, char[] password)
        {
            if (password == null)
                throw new ArgumentNullException(nameof(password));

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return GetKey(alias, password.AsSpan());
#else
            if (alias == null)
                throw new ArgumentNullException(nameof(alias));

            if (!m_keyEntries.TryGetValue(alias, out JksKeyEntry keyEntry))
                return null;

            var epki = keyEntry.keyInfo;
            if (!JksObfuscationAlg.Equals(epki.EncryptionAlgorithm))
                throw new IOException("unknown encryption algorithm");

            byte[] encryptedData = epki.GetEncryptedData();

            // key length is encryptedData - salt - checksum
            int pkcs8Len = encryptedData.Length - 40;

            IDigest digest = DigestUtilities.GetDigest("SHA-1");

            // key decryption
            byte[] pkcs8Key = CalculateKeyStream(digest, password, encryptedData, pkcs8Len);
            Bytes.XorTo(pkcs8Len, encryptedData, 20, pkcs8Key, 0);

            // integrity check
            byte[] checksum = GetKeyChecksum(digest, password, pkcs8Key);

            if (!Arrays.FixedTimeEquals(20, encryptedData, pkcs8Len + 20, checksum, 0))
                throw new IOException("cannot recover key");

            try
            {
                return PrivateKeyFactory.CreateKey(pkcs8Key);
            }
            finally
            {
                Array.Clear(pkcs8Key, 0, pkcs8Key.Length);
            }
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <exception cref="IOException"/>
        public AsymmetricKeyParameter GetKey(string alias, ReadOnlySpan<char> password)
        {
            if (alias == null)
                throw new ArgumentNullException(nameof(alias));

            if (!m_keyEntries.TryGetValue(alias, out JksKeyEntry keyEntry))
                return null;

            var epki = keyEntry.keyInfo;
            if (!JksObfuscationAlg.Equals(epki.EncryptionAlgorithm))
                throw new IOException("unknown encryption algorithm");

            byte[] encryptedData = epki.GetEncryptedData();

            // key length is encryptedData - salt - checksum
            int pkcs8Len = encryptedData.Length - 40;

            IDigest digest = DigestUtilities.GetDigest("SHA-1");

            // key decryption
            byte[] pkcs8Key = CalculateKeyStream(digest, password, encryptedData, pkcs8Len);
            Bytes.XorTo(pkcs8Len, encryptedData, 20, pkcs8Key, 0);

            // integrity check
            byte[] checksum = GetKeyChecksum(digest, password, pkcs8Key);

            if (!Arrays.FixedTimeEquals(20, encryptedData, pkcs8Len + 20, checksum, 0))
                throw new IOException("cannot recover key");

            try
            {
                return PrivateKeyFactory.CreateKey(pkcs8Key);
            }
            finally
            {
                Array.Clear(pkcs8Key, 0, pkcs8Key.Length);
            }
        }
#endif

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private byte[] GetKeyChecksum(IDigest digest, ReadOnlySpan<char> password, ReadOnlySpan<byte> pkcs8Key)
        {
            AddPassword(digest, password);

            return DigestUtilities.DoFinal(digest, pkcs8Key);
        }
#else
        private byte[] GetKeyChecksum(IDigest digest, char[] password, byte[] pkcs8Key)
        {
            AddPassword(digest, password);

            return DigestUtilities.DoFinal(digest, pkcs8Key);
        }
#endif

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private byte[] CalculateKeyStream(IDigest digest, ReadOnlySpan<char> password, ReadOnlySpan<byte> salt,
            int count)
        {
            byte[] keyStream = new byte[count];

            Span<byte> hash = stackalloc byte[20];
            hash.CopyFrom(salt);

            int index = 0;
            while (index < count)
            {
                AddPassword(digest, password);

                digest.BlockUpdate(hash);
                digest.DoFinal(hash);

                int length = System.Math.Min(hash.Length, keyStream.Length - index);
                keyStream.AsSpan(index, length).CopyFrom(hash);
                index += length;
            }

            return keyStream;
        }
#else
        private byte[] CalculateKeyStream(IDigest digest, char[] password, byte[] salt, int count)
        {
            byte[] keyStream = new byte[count];
            byte[] hash = Arrays.CopyOf(salt, 20);

            int index = 0;
            while (index < count)
            {
                AddPassword(digest, password);

                digest.BlockUpdate(hash, 0, hash.Length);
                digest.DoFinal(hash, 0);

                int length = System.Math.Min(hash.Length, keyStream.Length - index);
                Array.Copy(hash, 0, keyStream, index, length);
                index += length;
            }

            return keyStream;
        }
#endif

        public X509Certificate[] GetCertificateChain(string alias)
        {
            if (m_keyEntries.TryGetValue(alias, out var keyEntry))
                return CloneChain(keyEntry.chain);

            return null;
        }

        public X509Certificate GetCertificate(string alias)
        {
            if (m_certificateEntries.TryGetValue(alias, out var certEntry))
                return certEntry.cert;

            if (m_keyEntries.TryGetValue(alias, out var keyEntry))
            {
                var chain = keyEntry.chain;
                return chain == null || chain.Length == 0 ? null : chain[0];
            }

            return null;
        }

        public DateTime? GetCreationDate(string alias)
        {
            if (m_certificateEntries.TryGetValue(alias, out var certEntry))
                return certEntry.date;

            if (m_keyEntries.TryGetValue(alias, out var keyEntry))
                return keyEntry.date;

            return null;
        }

        /// <exception cref="IOException"/>
        public void SetKeyEntry(string alias, AsymmetricKeyParameter key, char[] password, X509Certificate[] chain)
        {
            if (password == null)
                throw new ArgumentNullException(nameof(password));

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            SetKeyEntry(alias, key, password.AsSpan(), chain);
#else
            alias = ConvertAlias(alias);

            if (ContainsAlias(alias))
                throw new IOException("alias [" + alias + "] already in use");

            byte[] pkcs8Key = PrivateKeyInfoFactory.CreatePrivateKeyInfo(key).GetEncoded();
            byte[] protectedKey = new byte[pkcs8Key.Length + 40];

            SecureRandom rnd = CryptoServicesRegistrar.GetSecureRandom();
            rnd.NextBytes(protectedKey, 0, 20);

            IDigest digest = DigestUtilities.GetDigest("SHA-1");

            // integrity protection
            byte[] checksum = GetKeyChecksum(digest, password, pkcs8Key);
            Array.Copy(checksum, 0, protectedKey, 20 + pkcs8Key.Length, 20);

            // key encryption
            byte[] keyStream = CalculateKeyStream(digest, password, protectedKey, pkcs8Key.Length);
            Bytes.Xor(pkcs8Key.Length, pkcs8Key, 0, keyStream, 0, protectedKey, 20);
            Array.Clear(keyStream, 0, keyStream.Length);

            try
            {
                var encryptedData = DerOctetString.WithContents(protectedKey);
                var epki = new EncryptedPrivateKeyInfo(JksObfuscationAlg, encryptedData);
                m_keyEntries.Add(alias, new JksKeyEntry(DateTime.UtcNow, epki, CloneChain(chain)));
            }
            catch (Exception e)
            {
                throw new IOException("unable to encode encrypted private key", e);
            }
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <exception cref="IOException"/>
        public void SetKeyEntry(string alias, AsymmetricKeyParameter key, ReadOnlySpan<char> password,
            X509Certificate[] chain)
        {
            alias = ConvertAlias(alias);

            if (ContainsAlias(alias))
                throw new IOException("alias [" + alias + "] already in use");

            byte[] pkcs8Key = PrivateKeyInfoFactory.CreatePrivateKeyInfo(key).GetEncoded();
            byte[] protectedKey = new byte[pkcs8Key.Length + 40];

            SecureRandom rnd = CryptoServicesRegistrar.GetSecureRandom();
            rnd.NextBytes(protectedKey, 0, 20);

            IDigest digest = DigestUtilities.GetDigest("SHA-1");

            // integrity protection
            byte[] checksum = GetKeyChecksum(digest, password, pkcs8Key);
            Array.Copy(checksum, 0, protectedKey, 20 + pkcs8Key.Length, 20);

            // key encryption
            byte[] keyStream = CalculateKeyStream(digest, password, protectedKey, pkcs8Key.Length);
            Bytes.Xor(pkcs8Key.Length, pkcs8Key, 0, keyStream, 0, protectedKey, 20);
            Array.Clear(keyStream, 0, keyStream.Length);

            try
            {
                var encryptedData = DerOctetString.WithContents(protectedKey);
                var epki = new EncryptedPrivateKeyInfo(JksObfuscationAlg, encryptedData);
                m_keyEntries.Add(alias, new JksKeyEntry(DateTime.UtcNow, epki, CloneChain(chain)));
            }
            catch (Exception e)
            {
                throw new IOException("unable to encode encrypted private key", e);
            }
        }
#endif

        /// <exception cref="IOException"/>
        public void SetKeyEntry(string alias, byte[] key, X509Certificate[] chain)
        {
            alias = ConvertAlias(alias);

            if (ContainsAlias(alias))
                throw new IOException("alias [" + alias + "] already in use");

            m_keyEntries.Add(alias, new JksKeyEntry(DateTime.UtcNow, key, CloneChain(chain)));
        }

        /// <exception cref="IOException"/>
        public void SetCertificateEntry(string alias, X509Certificate cert)
        {
            alias = ConvertAlias(alias);

            if (ContainsAlias(alias))
                throw new IOException("alias [" + alias + "] already in use");

            m_certificateEntries.Add(alias, new JksTrustedCertEntry(DateTime.UtcNow, cert));
        }

        public void DeleteEntry(string alias)
        {
            if (!m_keyEntries.Remove(alias))
            {
                m_certificateEntries.Remove(alias);
            }
        }

        public IEnumerable<string> Aliases
        {
            get
            {
                var aliases = new HashSet<string>(m_certificateEntries.Keys);
                aliases.UnionWith(m_keyEntries.Keys);
                return CollectionUtilities.Proxy(aliases);
            }
        }

        public bool ContainsAlias(string alias)
        {
            return IsCertificateEntry(alias) || IsKeyEntry(alias);
        }

        public int Count
        {
            get { return m_certificateEntries.Count + m_keyEntries.Count; }
        }

        public bool IsKeyEntry(string alias)
        {
            return m_keyEntries.ContainsKey(alias);
        }

        public bool IsCertificateEntry(string alias)
        {
            return m_certificateEntries.ContainsKey(alias);
        }

        public string GetCertificateAlias(X509Certificate cert)
        {
            foreach (var entry in m_certificateEntries)
            {
                if (entry.Value.cert.Equals(cert))
                    return entry.Key;
            }
            return null;
        }

        /// <exception cref="IOException"/>
        public void Save(Stream stream, char[] password)
        {
            if (password == null)
                throw new ArgumentNullException(nameof(password));

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Save(stream, password.AsSpan());
#else
            if (stream == null)
                throw new ArgumentNullException(nameof(stream));

            IDigest checksumDigest = CreateChecksumDigest(password);

            SaveStream(stream, checksumDigest);
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <exception cref="IOException"/>
        public void Save(Stream stream, ReadOnlySpan<char> password)
        {
            if (stream == null)
                throw new ArgumentNullException(nameof(stream));

            IDigest checksumDigest = CreateChecksumDigest(password);

            SaveStream(stream, checksumDigest);
        }
#endif

        private void SaveStream(Stream stream, IDigest checksumDigest)
        {
            BinaryWriter bw = new BinaryWriter(new DigestStream(stream, null, checksumDigest));

            BinaryWriters.WriteInt32BigEndian(bw, Magic);
            BinaryWriters.WriteInt32BigEndian(bw, 2);

            BinaryWriters.WriteInt32BigEndian(bw, Count);

            foreach (var entry in m_keyEntries)
            {
                string alias = entry.Key;
                JksKeyEntry keyEntry = entry.Value;

                BinaryWriters.WriteInt32BigEndian(bw, 1);
                WriteUtf(bw, alias);
                WriteDateTime(bw, keyEntry.date);
                WriteBufferWithInt32Length(bw, keyEntry.keyInfo.GetEncoded());

                X509Certificate[] chain = keyEntry.chain;
                int chainLength = chain == null ? 0 : chain.Length;
                BinaryWriters.WriteInt32BigEndian(bw, chainLength);
                for (int i = 0; i < chainLength; ++i)
                {
                    WriteTypedCertificate(bw, chain[i]);
                }
            }

            foreach (var entry in m_certificateEntries)
            {
                string alias = entry.Key;
                JksTrustedCertEntry certEntry = entry.Value;

                BinaryWriters.WriteInt32BigEndian(bw, 2);
                WriteUtf(bw, alias);
                WriteDateTime(bw, certEntry.date);
                WriteTypedCertificate(bw, certEntry.cert);
            }

            byte[] checksum = DigestUtilities.DoFinal(checksumDigest);
            bw.Write(checksum);
            bw.Flush();
        }

        /// <remarks>WARNING: If <paramref name="password"/> is <c>null</c>, no integrity check is performed.</remarks>
        /// <exception cref="IOException"/>
        public void Load(Stream stream, char[] password)
        {
            if (stream == null)
                throw new ArgumentNullException(nameof(stream));

            using (var storeStream = ValidateStream(stream, password))
            {
                LoadStream(storeStream);
            }
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <exception cref="IOException"/>
        public void Load(Stream stream, ReadOnlySpan<char> password)
        {
            if (stream == null)
                throw new ArgumentNullException(nameof(stream));

            using (var storeStream = ValidateStream(stream, password))
            {
                LoadStream(storeStream);
            }
        }
#endif

        /// <summary>Load without any integrity check.</summary>
        /// <exception cref="IOException"/>
        public void LoadUnchecked(Stream stream)
        {
            Load(stream, null);
        }

        private void LoadStream(ErasableByteStream storeStream)
        {
            m_certificateEntries.Clear();
            m_keyEntries.Clear();

            BinaryReader br = new BinaryReader(storeStream);

            int magic = BinaryReaders.ReadInt32BigEndian(br);
            int storeVersion = BinaryReaders.ReadInt32BigEndian(br);

            if (!(magic == Magic && (storeVersion == 1 || storeVersion == 2)))
                throw new IOException("Invalid keystore format");

            int numEntries = BinaryReaders.ReadInt32BigEndian(br);

            for (int t = 0; t < numEntries; t++)
            {
                int tag = BinaryReaders.ReadInt32BigEndian(br);

                switch (tag)
                {
                case 1: // keys
                {
                    string alias = ReadUtf(br);
                    DateTime date = ReadDateTime(br);

                    // encrypted key data
                    byte[] keyData = ReadBufferWithInt32Length(br);

                    // certificate chain
                    int chainLength = BinaryReaders.ReadInt32BigEndian(br);
                    X509Certificate[] chain = null;
                    if (chainLength > 0)
                    {
                        var certs = new List<X509Certificate>(System.Math.Min(10, chainLength));
                        for (int certNo = 0; certNo != chainLength; certNo++)
                        {
                            certs.Add(ReadTypedCertificate(br, storeVersion));
                        }
                        chain = certs.ToArray();
                    }
                    m_keyEntries.Add(alias, new JksKeyEntry(date, keyData, chain));
                    break;
                }
                case 2: // certificate
                {
                    string alias = ReadUtf(br);
                    DateTime date = ReadDateTime(br);

                    X509Certificate cert = ReadTypedCertificate(br, storeVersion);

                    m_certificateEntries.Add(alias, new JksTrustedCertEntry(date, cert));
                    break;
                }
                default:
                    throw new IOException("unable to discern entry type");
                }
            }

            if (storeStream.Position != storeStream.Length)
                throw new IOException("password incorrect or store tampered with");
        }

        /*
         * Validate password takes the checksum of the store and will either.
         * 1. If password is null, load the store into memory, return the result.
         * 2. If password is not null, load the store into memory, test the checksum, and if successful return
         * a new input stream instance of the store.
         * 3. Fail if there is a password and an invalid checksum.
         *
         * @param inputStream The input stream.
         * @param password    the password.
         * @return Either the passed in input stream or a new input stream.
         */
        /// <exception cref="IOException"/>
        private ErasableByteStream ValidateStream(Stream inputStream, char[] password)
        {
            byte[] rawStore = Streams.ReadAll(inputStream);
            int checksumPos = rawStore.Length - 20;

            if (password != null)
            {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                byte[] checksum = CalculateChecksum(password, rawStore.AsSpan(0, checksumPos));
#else
                byte[] checksum = CalculateChecksum(password, rawStore, 0, checksumPos);
#endif

                if (!Arrays.FixedTimeEquals(20, checksum, 0, rawStore, checksumPos))
                {
                    Array.Clear(rawStore, 0, rawStore.Length);
                    throw new IOException("password incorrect or store tampered with");
                }
            }

            return new ErasableByteStream(rawStore, 0, checksumPos);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <exception cref="IOException"/>
        private ErasableByteStream ValidateStream(Stream inputStream, ReadOnlySpan<char> password)
        {
            byte[] rawStore = Streams.ReadAll(inputStream);
            int checksumPos = rawStore.Length - 20;

            byte[] checksum = CalculateChecksum(password, rawStore.AsSpan(0, checksumPos));

            if (!Arrays.FixedTimeEquals(20, checksum, 0, rawStore, checksumPos))
            {
                Array.Clear(rawStore, 0, rawStore.Length);
                throw new IOException("password incorrect or store tampered with");
            }

            return new ErasableByteStream(rawStore, 0, checksumPos);
        }
#endif

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private static void AddPassword(IDigest digest, ReadOnlySpan<char> password)
        {
            // Encoding.BigEndianUnicode
            for (int i = 0; i < password.Length; ++i)
            {
                digest.Update((byte)(password[i] >> 8));
                digest.Update((byte)password[i]);
            }
        }
#else
        private static void AddPassword(IDigest digest, char[] password)
        {
            // Encoding.BigEndianUnicode
            for (int i = 0; i < password.Length; ++i)
            {
                digest.Update((byte)(password[i] >> 8));
                digest.Update((byte)password[i]);
            }
        }
#endif

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private static byte[] CalculateChecksum(ReadOnlySpan<char> password, ReadOnlySpan<byte> buffer)
        {
            IDigest checksumDigest = CreateChecksumDigest(password);
            checksumDigest.BlockUpdate(buffer);
            return DigestUtilities.DoFinal(checksumDigest);
        }
#else
        private static byte[] CalculateChecksum(char[] password, byte[] buffer, int offset, int length)
        {
            IDigest checksumDigest = CreateChecksumDigest(password);
            checksumDigest.BlockUpdate(buffer, offset, length);
            return DigestUtilities.DoFinal(checksumDigest);
        }
#endif

        private static X509Certificate[] CloneChain(X509Certificate[] chain)
        {
            return (X509Certificate[])chain?.Clone();
        }

        private static string ConvertAlias(string alias)
        {
            return alias.ToLowerInvariant();
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private static IDigest CreateChecksumDigest(ReadOnlySpan<char> password)
        {
            IDigest digest = DigestUtilities.GetDigest("SHA-1");
            AddPassword(digest, password);

            //
            // This "Mighty Aphrodite" string goes all the way back to the
            // first java betas in the mid 90's, why who knows? But see
            // https://cryptosense.com/mighty-aphrodite-dark-secrets-of-the-java-keystore/
            //
            byte[] prefix = Encoding.UTF8.GetBytes("Mighty Aphrodite");
            digest.BlockUpdate(prefix);
            return digest;
        }
#else
        private static IDigest CreateChecksumDigest(char[] password)
        {
            IDigest digest = DigestUtilities.GetDigest("SHA-1");
            AddPassword(digest, password);

            //
            // This "Mighty Aphrodite" string goes all the way back to the
            // first java betas in the mid 90's, why who knows? But see
            // https://cryptosense.com/mighty-aphrodite-dark-secrets-of-the-java-keystore/
            //
            byte[] prefix = Encoding.UTF8.GetBytes("Mighty Aphrodite");
            digest.BlockUpdate(prefix, 0, prefix.Length);
            return digest;
        }
#endif

        private static byte[] ReadBufferWithInt16Length(BinaryReader br)
        {
            int length = BinaryReaders.ReadInt16BigEndian(br);
            return BinaryReaders.ReadBytesFully(br, length);
        }

        private static byte[] ReadBufferWithInt32Length(BinaryReader br)
        {
            int length = BinaryReaders.ReadInt32BigEndian(br);
            return BinaryReaders.ReadBytesFully(br, length);
        }

        private static DateTime ReadDateTime(BinaryReader br)
        {
            long unixMS = BinaryReaders.ReadInt64BigEndian(br);
            return DateTimeUtilities.UnixMsToDateTime(unixMS);
        }

        private static X509Certificate ReadTypedCertificate(BinaryReader br, int storeVersion)
        {
            if (storeVersion == 2)
            {
                string certFormat = ReadUtf(br);
                if ("X.509" != certFormat)
                    throw new IOException("Unsupported certificate format: " + certFormat);
            }

            byte[] certData = ReadBufferWithInt32Length(br);
            try
            {
                return new X509Certificate(certData);
            }
            finally
            {
                Array.Clear(certData, 0, certData.Length);
            }
        }

        private static string ReadUtf(BinaryReader br)
        {
            byte[] mUtfBytes = ReadBufferWithInt16Length(br);

            int i = 0;
            MemoryStream utfBytes = new MemoryStream(mUtfBytes.Length);

            while (i < mUtfBytes.Length)
            {
                // Modified UTF-8 differs from regular UTF-8 in the following
                // ways:
                //
                // 1. NULL bytes never occur in the stream and are always
                //    two-byte encoded.
                // 2. There are no four-byte values and are instead always
                //    encoded using surrogate pairs.
                //
                // See also: https://docs.oracle.com/en/java/javase/16/docs/api/java.base/java/io/DataInput.html#modified-utf-8
                byte mUtfByte = mUtfBytes[i];
                if (mUtfByte == 0)
                    throw new NotSupportedException("Unexpected NULL byte in modified UTF-8 encoding in JKS");

                if ((mUtfByte & 0x80) == 0)
                {
                    // No transformation is applied to non-NULL ASCII bytes.
                    utfBytes.WriteByte(mUtfByte);
                    i += 1;
                }
                else if ((mUtfByte & 0xE0) == 0xC0)
                {
                    // Validate we have another byte.
                    if ((i + 1) >= mUtfBytes.Length)
                        throw new NotSupportedException("Two-byte sentinel found at end of input stream");

                    byte mUtfByteSecond = mUtfBytes[i+1];
                    if ((mUtfByteSecond & 0xC0) != 0x80)
                        throw new NotSupportedException("Second byte in two-byte modified UTF-8 encoding malformed");

                    // We might have encoded the NULL byte as two bytes.
                    if (mUtfByte == 0xC0 && mUtfByteSecond == 0x80)
                    {
                        utfBytes.WriteByte(0x00);
                    } else {
                        utfBytes.WriteByte(mUtfByte);
                        utfBytes.WriteByte(mUtfByteSecond);
                    }

                    i += 2;
                }
                else if ((mUtfByte & 0xF0) == 0xE0)
                {
                    // Validate we have enough bytes.
                    if ((i + 2) >= mUtfBytes.Length)
                        throw new NotSupportedException("Three-byte sentinel found at end of input stream");

                    byte mUtfByteSecond = mUtfBytes[i+1];
                    if ((mUtfByteSecond & 0xC0) != 0x80)
                        throw new NotSupportedException("Second byte in two-byte modified UTF-8 encoding malformed");

                    byte mUtfByteThird = mUtfBytes[i+2];
                    if ((mUtfByteThird & 0xC0) != 0x80)
                        throw new NotSupportedException("Third byte in two-byte modified UTF-8 encoding malformed");

                    utfBytes.WriteByte(mUtfByte);
                    utfBytes.WriteByte(mUtfByteSecond);
                    utfBytes.WriteByte(mUtfByteThird);

                    i += 3;
                }
                else
                {
                    // Reachable when we have a non-standard four-byte sentinel mask.
                    throw new NotSupportedException("Malformed modified UTF-8 encoding at index " + i);
                }
            }

            return Encoding.UTF8.GetString(utfBytes.ToArray());
        }

        private static void WriteBufferWithInt32Length(BinaryWriter bw, byte[] buffer)
        {
            BinaryWriters.WriteInt32BigEndian(bw, buffer.Length);
            bw.Write(buffer);
        }

        private static void WriteDateTime(BinaryWriter bw, DateTime dateTime)
        {
            long unixMS = DateTimeUtilities.DateTimeToUnixMs(dateTime);
            BinaryWriters.WriteInt64BigEndian(bw, unixMS);
        }

        private static void WriteTypedCertificate(BinaryWriter bw, X509Certificate cert)
        {
            WriteUtf(bw, "X.509");
            WriteBufferWithInt32Length(bw, cert.GetEncodedInternal());
        }

        private static void WriteUtf(BinaryWriter bw, string s)
        {
            byte[] utfBytes = Encoding.UTF8.GetBytes(s);

            int i = 0;
            MemoryStream mUtfBytes = new MemoryStream();
            while (i < utfBytes.Length)
            {
                byte utfByte = utfBytes[i];
                if (utfByte == 0)
                {
                    // The NULL byte is encoded in two byte format.
                    mUtfBytes.WriteByte(0xC0);
                    mUtfBytes.WriteByte(0x80);
                    i += 1;
                }
                else if ((utfByte & 0x80) == 0)
                {
                    // One byte UTF-8 bytes are written directly.
                    mUtfBytes.WriteByte(utfByte);
                    i += 1;
                }
                else if ((utfByte & 0xE0) == 0xC0)
                {
                    // Two byte UTF-8 values are preserved as-is.
                    if ((i + 1) >= utfBytes.Length)
                        throw new NotSupportedException("Malformed UTF-8: trailing two-byte character at end of string");

                    if ((utfBytes[i+1] & 0xC0) != 0x80)
                        throw new NotSupportedException("Malformed UTF-8: second byte has invalid prefix");

                    mUtfBytes.WriteByte(utfByte);
                    mUtfBytes.WriteByte(utfBytes[i+1]);
                    i += 2;
                }
                else if ((utfByte & 0xF0) == 0xE0)
                {
                    // Three byte UTF-8 values are preserved as-is.
                    if ((i + 2) >= utfBytes.Length)
                        throw new NotSupportedException("Malformed UTF-8: trailing three-byte character at end of string");

                    if ((utfBytes[i+1] & 0xC0) != 0x80)
                        throw new NotSupportedException("Malformed UTF-8: second byte has invalid prefix");

                    if ((utfBytes[i+2] & 0xC0) != 0x80)
                        throw new NotSupportedException("Malformed UTF-8: third byte has invalid prefix");

                    mUtfBytes.WriteByte(utfByte);
                    mUtfBytes.WriteByte(utfBytes[i+1]);
                    mUtfBytes.WriteByte(utfBytes[i+2]);
                    i += 3;

                }
                else
                {
                    // Reachable when we have a non-standard four-byte sentinel mask.
                    throw new NotSupportedException("Malformed modified UTF-8 encoding at index " + i);
                }
            }

            byte[] buffer = mUtfBytes.GetBuffer();
            short length = Convert.ToInt16(mUtfBytes.Length);

            BinaryWriters.WriteInt16BigEndian(bw, length);
            bw.Write(buffer, 0, length);
        }

        /**
         * JksTrustedCertEntry is a internal container for the certificate entry.
         */
        private sealed class JksTrustedCertEntry
        {
            internal readonly DateTime date;
            internal readonly X509Certificate cert;

            internal JksTrustedCertEntry(DateTime date, X509Certificate cert)
            {
                this.date = date;
                this.cert = cert;
            }
        }

        private sealed class JksKeyEntry
        {
            internal readonly DateTime date;
            internal readonly EncryptedPrivateKeyInfo keyInfo;
            internal readonly X509Certificate[] chain;

            internal JksKeyEntry(DateTime date, byte[] keyInfoEncoding, X509Certificate[] chain)
                : this(date, EncryptedPrivateKeyInfo.GetInstance(keyInfoEncoding), chain)
            {
            }

            internal JksKeyEntry(DateTime date, EncryptedPrivateKeyInfo keyInfo, X509Certificate[] chain)
            {
                this.date = date;
                this.keyInfo = keyInfo;
                this.chain = chain;
            }
        }

        private sealed class ErasableByteStream
            : MemoryStream
        {
            internal ErasableByteStream(byte[] buffer, int index, int count)
                : base(buffer, index, count, false, true)
            {
            }

            protected override void Dispose(bool disposing)
            {
                if (disposing)
                {
                    Position = 0L;

                    byte[] rawStore = GetBuffer();
                    Array.Clear(rawStore, 0, rawStore.Length);
                }
                base.Dispose(disposing);
            }
        }
    }
}
