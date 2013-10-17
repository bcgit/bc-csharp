using System.IO;
using Org.BouncyCastle.Utilities.IO;
using Org.BouncyCastle.Crypto.Macs;
using System;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Pkcs;
using System.Collections.Generic;
using System.Collections;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Date;

namespace Org.BouncyCastle.Crypto.Tls
{

    /**
     * Some helper functions for MicroTLS.
     */
    public static class TlsUtilities
    {
        public static byte[] EMPTY_BYTES = new byte[0];

        public static readonly ExtensionType EXT_signature_algorithms = ExtensionType.signature_algorithms;

        public static void CheckUint8(short i)
        {
            if (!IsValidUint8(i))
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }
        }

        public static void CheckUint8(int i)
        {
            if (!IsValidUint8(i))
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }
        }

        public static void CheckUint16(int i)
        {
            if (!IsValidUint16(i))
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }
        }

        public static void CheckUint24(int i)
        {
            if (!IsValidUint24(i))
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }
        }

        public static void CheckUint32(long i)
        {
            if (!IsValidUint32(i))
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }
        }

        public static void CheckUint48(long i)
        {
            if (!IsValidUint48(i))
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }
        }

        public static void CheckUint64(long i)
        {
            if (!IsValidUint64(i))
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }
        }

        public static bool IsValidUint8(short i)
        {
            return (i & 0xFF) == i;
        }

        public static bool IsValidUint8(int i)
        {
            return (i & 0xFF) == i;
        }

        public static bool IsValidUint16(int i)
        {
            return (i & 0xFFFF) == i;
        }

        public static bool IsValidUint24(int i)
        {
            return (i & 0xFFFFFF) == i;
        }

        public static bool IsValidUint32(long i)
        {
            return (i & 0xFFFFFFFFL) == i;
        }

        public static bool IsValidUint48(long i)
        {
            return (i & 0xFFFFFFFFFFFFL) == i;
        }

        public static bool IsValidUint64(long i)
        {
            return true;
        }

        public static bool IsSSL(TlsContext context)
        {
            return context.ServerVersion.IsSSL;
        }

        public static bool IsTLSv11(TlsContext context)
        {
            return ProtocolVersion.TLSv11.IsEqualOrEarlierVersionOf(context.ServerVersion.EquivalentTLSVersion);
        }

        public static bool IsTLSv12(TlsContext context)
        {
            return ProtocolVersion.TLSv12.IsEqualOrEarlierVersionOf(context.ServerVersion.EquivalentTLSVersion);
        }

        public static void WriteUint8(short i, Stream output)
        {
            output.WriteByte((byte)i);
        }

        public static void WriteUint8(int i, Stream output)
        {
            output.WriteByte((byte)i);
        }

        public static void WriteUint8(short i, byte[] buf, int offset)
        {
            buf[offset] = (byte)i;
        }

        public static void WriteUint8(int i, byte[] buf, int offset)
        {
            buf[offset] = (byte)i;
        }

        public static void WriteUint16(int i, Stream output)
        {
            output.WriteByte((byte)(i >> 8));
            output.WriteByte((byte)i);
        }

        public static void WriteUint16(int i, byte[] buf, int offset)
        {
            buf[offset] = (byte)(i >> 8);
            buf[offset + 1] = (byte)i;
        }

        public static void WriteUint24(int i, Stream output)
        {
            output.WriteByte((byte)(i >> 16));
            output.WriteByte((byte)(i >> 8));
            output.WriteByte((byte)i);
        }

        public static void WriteUint24(int i, byte[] buf, int offset)
        {
            buf[offset] = (byte)(i >> 16);
            buf[offset + 1] = (byte)(i >> 8);
            buf[offset + 2] = (byte)(i);
        }

        public static void WriteUint32(long i, Stream output)
        {
            output.WriteByte((byte)(i >> 24));
            output.WriteByte((byte)(i >> 16));
            output.WriteByte((byte)(i >> 8));
            output.WriteByte((byte)(i));
        }

        public static void WriteUint32(long i, byte[] buf, int offset)
        {
            buf[offset] = (byte)(i >> 24);
            buf[offset + 1] = (byte)(i >> 16);
            buf[offset + 2] = (byte)(i >> 8);
            buf[offset + 3] = (byte)(i);
        }

        public static void WriteUint48(long i, Stream output)
        {
            output.WriteByte((byte)(i >> 40));
            output.WriteByte((byte)(i >> 32));
            output.WriteByte((byte)(i >> 24));
            output.WriteByte((byte)(i >> 16));
            output.WriteByte((byte)(i >> 8));
            output.WriteByte((byte)(i));
        }

        public static void WriteUint48(long i, byte[] buf, int offset)
        {
            buf[offset] = (byte)(i >> 40);
            buf[offset + 1] = (byte)(i >> 32);
            buf[offset + 2] = (byte)(i >> 24);
            buf[offset + 3] = (byte)(i >> 16);
            buf[offset + 4] = (byte)(i >> 8);
            buf[offset + 5] = (byte)(i);
        }

        public static void WriteUint64(long i, Stream output)
        {
            output.WriteByte((byte)(i >> 56));
            output.WriteByte((byte)(i >> 48));
            output.WriteByte((byte)(i >> 40));
            output.WriteByte((byte)(i >> 32));
            output.WriteByte((byte)(i >> 24));
            output.WriteByte((byte)(i >> 16));
            output.WriteByte((byte)(i >> 8));
            output.WriteByte((byte)(i));
        }

        public static void WriteUint64(long i, byte[] buf, int offset)
        {
            buf[offset] = (byte)(i >> 56);
            buf[offset + 1] = (byte)(i >> 48);
            buf[offset + 2] = (byte)(i >> 40);
            buf[offset + 3] = (byte)(i >> 32);
            buf[offset + 4] = (byte)(i >> 24);
            buf[offset + 5] = (byte)(i >> 16);
            buf[offset + 6] = (byte)(i >> 8);
            buf[offset + 7] = (byte)(i);
        }

        public static void WriteOpaque8(byte[] buf, Stream output)
        {
            CheckUint8(buf.Length);
            WriteUint8(buf.Length, output);
            output.Write(buf, 0, buf.Length);
        }

        public static void WriteOpaque16(byte[] buf, Stream output)
        {
            CheckUint16(buf.Length);
            WriteUint16(buf.Length, output);
            output.Write(buf, 0, buf.Length);
        }

        public static void WriteOpaque24(byte[] buf, Stream output)
        {
            CheckUint24(buf.Length);
            WriteUint24(buf.Length, output);
            output.Write(buf, 0, buf.Length);
        }

        public static void WriteUint8Array(short[] uints, Stream output)
        {
            for (int i = 0; i < uints.Length; ++i)
            {
                WriteUint8(uints[i], output);
            }
        }

        public static void WriteUint8Array(ECPointFormat[] uints, Stream output)
        {
            for (int i = 0; i < uints.Length; ++i)
            {
                WriteUint8((short)uints[i], output);
            }
        }


        public static void WriteUint8Array(CompressionMethod[] uints, Stream output)
        {
            for (int i = 0; i < uints.Length; ++i)
            {
                WriteUint8((byte)uints[i], output);
            }
        }

        public static void WriteUint8Array(ClientCertificateType[] uints, Stream output)
        {
            for (int i = 0; i < uints.Length; ++i)
            {
                WriteUint8((byte)uints[i], output);
            }
        }

        public static void WriteUint16Array(int[] uints, Stream output)
        {
            for (int i = 0; i < uints.Length; ++i)
            {
                WriteUint16(uints[i], output);
            }
        }

        public static void WriteUint16Array(CipherSuite[] uints, Stream output)
        {
            for (int i = 0; i < uints.Length; ++i)
            {
                WriteUint16((int)uints[i], output);
            }
        }        

        public static void WriteUint16Array(NamedCurve[] uints, Stream output)
        {
            for (int i = 0; i < uints.Length; ++i)
            {
                WriteUint16((int)uints[i], output);
            }
        }

        public static short ReadUint8(Stream input)
        {
            int i = input.ReadByte();
            if (i < 0)
            {
                throw new EndOfStreamException();
            }
            return (short)i;
        }

        public static short ReadUint8(byte[] buf, int offset)
        {
            return (short)buf[offset];
        }

        public static int ReadUint16(Stream input)
        {
            int i1 = input.ReadByte();
            int i2 = input.ReadByte();
            if (i2 < 0)
            {
                throw new EndOfStreamException();
            }
            return i1 << 8 | i2;
        }

        public static int ReadUint16(byte[] buf, int offset)
        {
            int n = (buf[offset] & 0xff) << 8;
            n |= (buf[++offset] & 0xff);
            return n;
        }

        public static int ReadUint24(Stream input)
        {
            int i1 = input.ReadByte();
            int i2 = input.ReadByte();
            int i3 = input.ReadByte();
            if (i3 < 0)
            {
                throw new EndOfStreamException();
            }
            return (i1 << 16) | (i2 << 8) | i3;
        }

        public static int ReadUint24(byte[] buf, int offset)
        {
            int n = (buf[offset] & 0xff) << 16;
            n |= (buf[++offset] & 0xff) << 8;
            n |= (buf[++offset] & 0xff);
            return n;
        }

        public static long ReadUint32(Stream input)
        {
            int i1 = input.ReadByte();
            int i2 = input.ReadByte();
            int i3 = input.ReadByte();
            int i4 = input.ReadByte();
            if (i4 < 0)
            {
                throw new EndOfStreamException();
            }
            return (long)((((long)i1) << 24) | (((long)i2) << 16) | (((long)i3) << 8) | ((long)i4));
        }

        public static long ReadUint48(Stream input)
        {
            int i1 = input.ReadByte();
            int i2 = input.ReadByte();
            int i3 = input.ReadByte();
            int i4 = input.ReadByte();
            int i5 = input.ReadByte();
            int i6 = input.ReadByte();
            if (i6 < 0)
            {
                throw new EndOfStreamException();
            }
            return (((long)i1) << 40) | (((long)i2) << 32) | (((long)i3) << 24) | (((long)i4) << 16) | (((long)i5) << 8) | ((long)i6);
        }

        public static long ReadUint48(byte[] buf, int offset)
        {
            int hi = ReadUint24(buf, offset);
            int lo = ReadUint24(buf, offset + 3);
            return ((long)(hi & 0xffffffffL) << 24) | (long)(lo & 0xffffffffL);
        }

        public static byte[] ReadAllOrNothing(int length, Stream input)
        {
            if (length < 1)
            {
                return EMPTY_BYTES;
            }
            byte[] buf = new byte[length];
            int read = Streams.ReadFully(input, buf);
            if (read == 0)
            {
                return null;
            }
            if (read != length)
            {
                throw new EndOfStreamException();
            }
            return buf;
        }

        public static byte[] ReadFully(int length, Stream input)
        {
            if (length < 1)
            {
                return EMPTY_BYTES;
            }
            byte[] buf = new byte[length];
            if (length != Streams.ReadFully(input, buf))
            {
                throw new EndOfStreamException();
            }
            return buf;
        }

        public static void ReadFully(byte[] buf, Stream input)
        {
            int length = buf.Length;
            if (length > 0 && length != Streams.ReadFully(input, buf))
            {
                throw new EndOfStreamException();
            }
        }

        public static byte[] ReadOpaque8(Stream input)
        {
            short length = ReadUint8(input);
            return ReadFully(length, input);
        }

        public static byte[] ReadOpaque16(Stream input)
        {
            int length = ReadUint16(input);
            return ReadFully(length, input);
        }

        public static byte[] ReadOpaque24(Stream input)
        {
            int length = ReadUint24(input);
            return ReadFully(length, input);
        }

        public static short[] ReadUint8Array(int count, Stream input)
        {
            short[] uints = new short[count];
            for (int i = 0; i < count; ++i)
            {
                uints[i] = ReadUint8(input);
            }
            return uints;
        }

        public static ECPointFormat[] ReadECPointFormats(int count, Stream input)
        {
            ECPointFormat[] uints = new ECPointFormat[count];

            for (int i = 0; i < count; ++i)
            {
                uints[i] = (ECPointFormat)ReadUint8(input);
            }

            return uints;
        }


        public static CompressionMethod[] ReadCompressionMethods(int count, Stream input)
        {
            CompressionMethod[] uints = new CompressionMethod[count];

            for (int i = 0; i < count; ++i)
            {
                uints[i] = (CompressionMethod)ReadUint8(input);
            }

            return uints;
        }

        public static int[] ReadUint16Array(int count, Stream input)
        {
            int[] uints = new int[count];
            for (int i = 0; i < count; ++i)
            {
                uints[i] = ReadUint16(input);
            }
            return uints;
        }

        public static NamedCurve[] ReadNamedCurveArray(int count, Stream input)
        {
            NamedCurve[] uints = new NamedCurve[count];
            for (int i = 0; i < count; ++i)
            {
                uints[i] = (NamedCurve)ReadUint16(input);
            }
            return uints;
        }

        public static CipherSuite[] ReadCipherSuiteArray(int count, Stream input)
        {
            CipherSuite[] uints = new CipherSuite[count];
            for (int i = 0; i < count; ++i)
            {
                uints[i] = (CipherSuite)ReadUint16(input);
            }
            return uints;
        }


        public static ProtocolVersion ReadVersion(byte[] buf, int offset)
        {
            return ProtocolVersion.Get(buf[offset] & 0xFF, buf[offset + 1] & 0xFF);
        }

        public static ProtocolVersion ReadVersion(Stream input)
        {
            int i1 = input.ReadByte();
            int i2 = input.ReadByte();
            if (i2 < 0)
            {
                throw new EndOfStreamException();
            }
            return ProtocolVersion.Get(i1, i2);
        }

        public static int ReadVersionRaw(byte[] buf, int offset)
        {
            return (buf[offset] << 8) | buf[offset + 1];
        }

        public static int ReadVersionRaw(Stream input)
        {
            int i1 = input.ReadByte();
            int i2 = input.ReadByte();
            if (i2 < 0)
            {
                throw new EndOfStreamException();
            }
            return (i1 << 8) | i2;
        }

        public static Asn1Object ReadAsn1Object(byte[] encoding)
        {
            Asn1InputStream asn1 = new Asn1InputStream(encoding);
            var result = asn1.ReadObject();
            if (null == result)
            {
                throw new TlsFatalAlert(AlertDescription.decode_error);
            }
            if (null != asn1.ReadObject())
            {
                throw new TlsFatalAlert(AlertDescription.decode_error);
            }
            return result;
        }

        public static Asn1Object ReadDerObject(byte[] encoding)
        {
            /*
             * NOTE: The current ASN.1 parsing code can't enforce DER-only parsing, but since DER is
             * canonical, we can check it by re-encoding the result and comparing to the original.
             */
            Asn1Object result = ReadAsn1Object(encoding);
            byte[] check = result.GetEncoded(Asn1Encodable.Der);
            if (!Arrays.AreEqual(check, encoding))
            {
                throw new TlsFatalAlert(AlertDescription.decode_error);
            }
            return result;
        }

        public static void WriteGMTUnixTime(byte[] buf, int offset)
        {
            int t = (int)(DateTimeUtilities.CurrentUnixMs() / 1000L);
            buf[offset] = (byte)(t >> 24);
            buf[offset + 1] = (byte)(t >> 16);
            buf[offset + 2] = (byte)(t >> 8);
            buf[offset + 3] = (byte)t;
        }

        public static void WriteVersion(ProtocolVersion version, Stream output)
        {
            output.WriteByte((byte)version.MajorVersion);
            output.WriteByte((byte)version.MinorVersion);
        }

        public static void WriteVersion(ProtocolVersion version, byte[] buf, int offset)
        {
            buf[offset] = (byte)version.MajorVersion;
            buf[offset + 1] = (byte)version.MinorVersion;
        }

        public static IList GetDefaultDSSSignatureAlgorithms()
        {
            return new SignatureAndHashAlgorithm[] { new SignatureAndHashAlgorithm(HashAlgorithm.sha1, SignatureAlgorithm.dsa) };
        }

        public static IList GetDefaultECDSASignatureAlgorithms()
        {
            return new SignatureAndHashAlgorithm[] { new SignatureAndHashAlgorithm(HashAlgorithm.sha1, SignatureAlgorithm.ecdsa) };
        }

        public static IList GetDefaultRSASignatureAlgorithms()
        {
            return new SignatureAndHashAlgorithm[] { new SignatureAndHashAlgorithm(HashAlgorithm.sha1, SignatureAlgorithm.rsa) };
        }

        public static byte[] GetExtensionData(IDictionary extensions, ExtensionType extensionType)
        {
            return extensions == null ? null : (byte[])extensions[extensionType];
        }

        public static bool HasExpectedEmptyExtensionData(IDictionary extensions, ExtensionType extensionType,
            AlertDescription alertDescription)
        {
            byte[] extension_data = GetExtensionData(extensions, extensionType);
            if (extension_data == null)
            {
                return false;
            }
            if (extension_data.Length != 0)
            {
                throw new TlsFatalAlert(alertDescription);
            }
            return true;
        }

        public static TlsSession ImportSession(byte[] sessionID, SessionParameters sessionParameters)
        {
            return new TlsSessionImpl(sessionID, sessionParameters);
        }

        public static bool IsSignatureAlgorithmsExtensionAllowed(ProtocolVersion clientVersion)
        {
            return ProtocolVersion.TLSv12.IsEqualOrEarlierVersionOf(clientVersion.EquivalentTLSVersion);
        }

        /**
         * Add a 'signature_algorithms' extension to existing extensions.
         *
         * @param extensions                   A {@link Hashtable} to add the extension to.
         * @param supportedSignatureAlgorithms {@link IList} containing at least 1 {@link SignatureAndHashAlgorithm}.
         * @throws IOException
         */
        public static void AddSignatureAlgorithmsExtension(IDictionary extensions, IList supportedSignatureAlgorithms)
        {
            extensions[EXT_signature_algorithms] = CreateSignatureAlgorithmsExtension(supportedSignatureAlgorithms);
        }

        /**
         * Get a 'signature_algorithms' extension from extensions.
         *
         * @param extensions A {@link Hashtable} to get the extension from, if it is present.
         * @return A {@link IList} containing at least 1 {@link SignatureAndHashAlgorithm}, or null.
         * @throws IOException
         */
        public static IList GetSignatureAlgorithmsExtension(IDictionary extensions)
        {
            byte[] extensionData = GetExtensionData(extensions, EXT_signature_algorithms);
            return extensionData == null ? null : ReadSignatureAlgorithmsExtension(extensionData);
        }

        /**
         * Create a 'signature_algorithms' extension value.
         *
         * @param supportedSignatureAlgorithms A {@link IList} containing at least 1 {@link SignatureAndHashAlgorithm}.
         * @return A byte array suitable for use as an extension value.
         * @throws IOException
         */
        public static byte[] CreateSignatureAlgorithmsExtension(IList supportedSignatureAlgorithms)
        {
            var buf = new MemoryStream();

            // supported_signature_algorithms
            EncodeSupportedSignatureAlgorithms(supportedSignatureAlgorithms, false, buf);

            return buf.ToArray();
        }

        /**
         * Read 'signature_algorithms' extension data.
         *
         * @param extensionData The extension data.
         * @return A {@link IList} containing at least 1 {@link SignatureAndHashAlgorithm}.
         * @throws IOException
         */
        public static IList ReadSignatureAlgorithmsExtension(byte[] extensionData)
        {
            if (extensionData == null)
            {
                throw new ArgumentException("'extensionData' cannot be null");
            }

            MemoryStream buf = new MemoryStream(extensionData);

            // supported_signature_algorithms
            var supported_signature_algorithms = ParseSupportedSignatureAlgorithms(false, buf);

            TlsProtocol.AssertEmpty(buf);

            return supported_signature_algorithms;
        }

        public static void EncodeSupportedSignatureAlgorithms(IList supportedSignatureAlgorithms, bool allowAnonymous,
            Stream output)
        {
            if (supportedSignatureAlgorithms == null || supportedSignatureAlgorithms.Count < 1
                || supportedSignatureAlgorithms.Count >= (1 << 15))
            {
                throw new ArgumentException(
                    "'supportedSignatureAlgorithms' must have length from 1 to (2^15 - 1)");
            }

            // supported_signature_algorithms
            int length = 2 * supportedSignatureAlgorithms.Count;
            TlsUtilities.CheckUint16(length);
            TlsUtilities.WriteUint16(length, output);
            for (int i = 0; i < supportedSignatureAlgorithms.Count; ++i)
            {
                SignatureAndHashAlgorithm entry = (SignatureAndHashAlgorithm)supportedSignatureAlgorithms[i];
                if (!allowAnonymous && entry.Signature == SignatureAlgorithm.anonymous)
                {
                    /*
                     * RFC 5246 7.4.1.4.1 The "anonymous" value is meaningless in this context but used
                     * in Section 7.4.3. It MUST NOT appear in this extension.
                     */
                    throw new ArgumentException(
                        "SignatureAlgorithm.anonymous MUST NOT appear in the signature_algorithms extension");
                }
                entry.Encode(output);
            }
        }

        public static List<SignatureAndHashAlgorithm> ParseSupportedSignatureAlgorithms(bool allowAnonymous, Stream input)
        {
            // supported_signature_algorithms
            int length = TlsUtilities.ReadUint16(input);
            if (length < 2 || (length & 1) != 0)
            {
                throw new TlsFatalAlert(AlertDescription.decode_error);
            }
            int count = length / 2;

            var supportedSignatureAlgorithms = new List<SignatureAndHashAlgorithm>(count);
            for (int i = 0; i < count; ++i)
            {
                SignatureAndHashAlgorithm entry = SignatureAndHashAlgorithm.Parse(input);
                if (!allowAnonymous && entry.Signature == SignatureAlgorithm.anonymous)
                {
                    /*
                     * RFC 5246 7.4.1.4.1 The "anonymous" value is meaningless in this context but used
                     * in Section 7.4.3. It MUST NOT appear in this extension.
                     */
                    throw new TlsFatalAlert(AlertDescription.illegal_parameter);
                }
                supportedSignatureAlgorithms.Add(entry);
            }
            return supportedSignatureAlgorithms;
        }

        public static byte[] PRF(TlsContext context, byte[] secret, String asciiLabel, byte[] seed, int size)
        {
            ProtocolVersion version = context.ServerVersion;

            if (version.IsSSL)
            {
                throw new InvalidOperationException("No PRF available for SSLv3 session");
            }

            byte[] label = Strings.ToByteArray(asciiLabel);
            byte[] labelSeed = Concat(label, seed);

            int prfAlgorithm = context.SecurityParameters.PrfAlgorithm;

            if (prfAlgorithm == PRFAlgorithm.tls_prf_legacy)
            {
                return PRF_legacy(secret, label, labelSeed, size);
            }

            IDigest prfDigest = CreatePRFHash(prfAlgorithm);
            byte[] buf = new byte[size];
            HmacHash(prfDigest, secret, labelSeed, buf);
            return buf;
        }

        static byte[] PRF_legacy(byte[] secret, byte[] label, byte[] labelSeed, int size)
        {
            int s_half = (secret.Length + 1) / 2;
            byte[] s1 = new byte[s_half];
            byte[] s2 = new byte[s_half];
            Buffer.BlockCopy(secret, 0, s1, 0, s_half);
            Buffer.BlockCopy(secret, secret.Length - s_half, s2, 0, s_half);

            byte[] b1 = new byte[size];
            byte[] b2 = new byte[size];
            HmacHash(new MD5Digest(), s1, labelSeed, b1);
            HmacHash(new Sha1Digest(), s2, labelSeed, b2);
            for (int i = 0; i < size; i++)
            {
                b1[i] ^= b2[i];
            }
            return b1;
        }

        internal static byte[] Concat(byte[] a, byte[] b)
        {
            byte[] c = new byte[a.Length + b.Length];
            Buffer.BlockCopy(a, 0, c, 0, a.Length);
            Buffer.BlockCopy(b, 0, c, a.Length, b.Length);
            return c;
        }

        internal static void HmacHash(IDigest digest, byte[] secret, byte[] seed, byte[] output)
        {
            HMac mac = new HMac(digest);
            KeyParameter param = new KeyParameter(secret);
            byte[] a = seed;
            int size = digest.GetDigestSize();
            int iterations = (output.Length + size - 1) / size;
            byte[] buf = new byte[mac.GetMacSize()];
            byte[] buf2 = new byte[mac.GetMacSize()];
            for (int i = 0; i < iterations; i++)
            {
                mac.Init(param);
                mac.BlockUpdate(a, 0, a.Length);
                mac.DoFinal(buf, 0);
                a = buf;
                mac.Init(param);
                mac.BlockUpdate(a, 0, a.Length);
                mac.BlockUpdate(seed, 0, seed.Length);
                mac.DoFinal(buf2, 0);
                Buffer.BlockCopy(buf2, 0, output, (size * i), System.Math.Min(size, output.Length - (size * i)));
            }
        }

        internal static void ValidateKeyUsage(X509CertificateStructure c, int keyUsageBits)
        {
            X509Extensions exts = c.TbsCertificate.Extensions;
            if (exts != null)
            {
                X509Extension ext = exts.GetExtension(X509Extensions.KeyUsage);
                if (ext != null)
                {
                    DerBitString ku = KeyUsage.GetInstance(ext);
                    int bits = ku.GetBytes()[0];
                    if ((bits & keyUsageBits) != keyUsageBits)
                    {
                        throw new TlsFatalAlert(AlertDescription.certificate_unknown);
                    }
                }
            }
        }

        internal static byte[] CalculateKeyBlock(TlsContext context, int size)
        {
            SecurityParameters securityParameters = context.SecurityParameters;
            byte[] master_secret = securityParameters.MasterSecret;
            byte[] seed = Concat(securityParameters.ServerRandom,
                securityParameters.ClientRandom);

            if (context.ServerVersion.IsSSL)
            {
                return CalculateKeyBlock_SSL(master_secret, seed, size);
            }

            return PRF(context, master_secret, ExporterLabel.key_expansion, seed, size);
        }

        internal static byte[] CalculateKeyBlock_SSL(byte[] master_secret, byte[] random, int size)
        {
            var md5 = new MD5Digest();
            var sha1 = new Sha1Digest();
            int md5Size = md5.GetDigestSize();
            byte[] shatmp = new byte[sha1.GetDigestSize()];
            byte[] tmp = new byte[size + md5Size];

            int i = 0, pos = 0;
            while (pos < size)
            {
                byte[] ssl3Const = SSL3_CONST[i];

                sha1.BlockUpdate(ssl3Const, 0, ssl3Const.Length);
                sha1.BlockUpdate(master_secret, 0, master_secret.Length);
                sha1.BlockUpdate(random, 0, random.Length);
                sha1.DoFinal(shatmp, 0);

                md5.BlockUpdate(master_secret, 0, master_secret.Length);
                md5.BlockUpdate(shatmp, 0, shatmp.Length);
                md5.DoFinal(tmp, pos);

                pos += md5Size;
                ++i;
            }

            byte[] rval = new byte[size];
            Buffer.BlockCopy(tmp, 0, rval, 0, size);
            return rval;
        }

        internal static byte[] CalculateMasterSecret(TlsContext context, byte[] pre_master_secret)
        {
            SecurityParameters securityParameters = context.SecurityParameters;
            byte[] seed = Concat(securityParameters.ClientRandom, securityParameters.ServerRandom);

            if (context.ServerVersion.IsSSL)
            {
                return CalculateMasterSecret_SSL(pre_master_secret, seed);
            }

            return PRF(context, pre_master_secret, ExporterLabel.master_secret, seed, 48);
        }

        internal static byte[] CalculateMasterSecret_SSL(byte[] pre_master_secret, byte[] random)
        {
            IDigest md5 = new MD5Digest();
            IDigest sha1 = new Sha1Digest();
            int md5Size = md5.GetDigestSize();
            byte[] shatmp = new byte[sha1.GetDigestSize()];

            byte[] rval = new byte[md5Size * 3];
            int pos = 0;

            for (int i = 0; i < 3; ++i)
            {
                byte[] ssl3Const = SSL3_CONST[i];

                sha1.BlockUpdate(ssl3Const, 0, ssl3Const.Length);
                sha1.BlockUpdate(pre_master_secret, 0, pre_master_secret.Length);
                sha1.BlockUpdate(random, 0, random.Length);
                sha1.DoFinal(shatmp, 0);

                md5.BlockUpdate(pre_master_secret, 0, pre_master_secret.Length);
                md5.BlockUpdate(shatmp, 0, shatmp.Length);
                md5.DoFinal(rval, pos);

                pos += md5Size;
            }

            return rval;
        }

        internal static byte[] CalculateVerifyData(TlsContext context, String asciiLabel, byte[] handshakeHash)
        {
            if (context.ServerVersion.IsSSL)
            {
                return handshakeHash;
            }

            SecurityParameters securityParameters = context.SecurityParameters;
            byte[] master_secret = securityParameters.MasterSecret;
            int verify_data_length = securityParameters.VerifyDataLength;

            return PRF(context, master_secret, asciiLabel, handshakeHash, verify_data_length);
        }

        public static IDigest CreateHash(int hashAlgorithm)
        {
            switch (hashAlgorithm)
            {
                case HashAlgorithm.md5:
                    return new MD5Digest();
                case HashAlgorithm.sha1:
                    return new Sha1Digest();
                case HashAlgorithm.sha224:
                    return new Sha224Digest();
                case HashAlgorithm.sha256:
                    return new Sha256Digest();
                case HashAlgorithm.sha384:
                    return new Sha384Digest();
                case HashAlgorithm.sha512:
                    return new Sha512Digest();
                default:
                    throw new ArgumentException("unknown HashAlgorithm");
            }
        }

        public static IDigest CloneHash(int hashAlgorithm, IDigest hash)
        {
            switch (hashAlgorithm)
            {
                case HashAlgorithm.md5:
                    return new MD5Digest((MD5Digest)hash);
                case HashAlgorithm.sha1:
                    return new Sha1Digest((Sha1Digest)hash);
                case HashAlgorithm.sha224:
                    return new Sha224Digest((Sha224Digest)hash);
                case HashAlgorithm.sha256:
                    return new Sha256Digest((Sha256Digest)hash);
                case HashAlgorithm.sha384:
                    return new Sha384Digest((Sha384Digest)hash);
                case HashAlgorithm.sha512:
                    return new Sha512Digest((Sha512Digest)hash);
                default:
                    throw new ArgumentException("unknown HashAlgorithm");
            }
        }

        public static IDigest CreatePRFHash(int prfAlgorithm)
        {
            switch (prfAlgorithm)
            {
                case PRFAlgorithm.tls_prf_legacy:
                    return new CombinedHash();
                default:
                    return CreateHash(GetHashAlgorithmForPRFAlgorithm(prfAlgorithm));
            }
        }

        public static IDigest ClonePRFHash(int prfAlgorithm, IDigest hash)
        {
            switch (prfAlgorithm)
            {
                case PRFAlgorithm.tls_prf_legacy:
                    return new CombinedHash((CombinedHash)hash);
                default:
                    return CloneHash(GetHashAlgorithmForPRFAlgorithm(prfAlgorithm), hash);
            }
        }

        public static short GetHashAlgorithmForPRFAlgorithm(int prfAlgorithm)
        {
            switch (prfAlgorithm)
            {
                case PRFAlgorithm.tls_prf_legacy:
                    throw new ArgumentException("legacy PRF not a valid algorithm");
                case PRFAlgorithm.tls_prf_sha256:
                    return HashAlgorithm.sha256;
                case PRFAlgorithm.tls_prf_sha384:
                    return HashAlgorithm.sha384;
                default:
                    throw new ArgumentException("unknown PRFAlgorithm");
            }
        }

        public static DerObjectIdentifier GetOIDForHashAlgorithm(int hashAlgorithm)
        {
            switch (hashAlgorithm)
            {
                case HashAlgorithm.md5:
                    return PkcsObjectIdentifiers.MD5;
                case HashAlgorithm.sha1:
                    return X509ObjectIdentifiers.IdSha1;
                case HashAlgorithm.sha224:
                    return NistObjectIdentifiers.IdSha224;
                case HashAlgorithm.sha256:
                    return NistObjectIdentifiers.IdSha256;
                case HashAlgorithm.sha384:
                    return NistObjectIdentifiers.IdSha384;
                case HashAlgorithm.sha512:
                    return NistObjectIdentifiers.IdSha512;
                default:
                    throw new ArgumentException("unknown HashAlgorithm");
            }
        }

        internal static ClientCertificateType GetClientCertificateType(Certificate clientCertificate, Certificate serverCertificate)
        {
            if (clientCertificate.IsEmpty)
            {
                return ClientCertificateType.empty;
            }

            X509CertificateStructure x509Cert = clientCertificate.certs[0];
            SubjectPublicKeyInfo keyInfo = x509Cert.SubjectPublicKeyInfo;
            try
            {
                AsymmetricKeyParameter publicKey = PublicKeyFactory.CreateKey(keyInfo);
                if (publicKey.IsPrivate)
                {
                    throw new TlsFatalAlert(AlertDescription.internal_error);
                }

                /*
                 * TODO RFC 5246 7.4.6. The certificates MUST be signed using an acceptable hash/
                 * signature algorithm pair, as described in Section 7.4.4. Note that this relaxes the
                 * constraints on certificate-signing algorithms found in prior versions of TLS.
                 */

                /*
                 * RFC 5246 7.4.6. Client Certificate
                 */

                /*
                 * RSA public key; the certificate MUST allow the key to be used for signing with the
                 * signature scheme and hash algorithm that will be employed in the certificate verify
                 * message.
                 */
                if (publicKey is RsaKeyParameters)
                {
                    ValidateKeyUsage(x509Cert, KeyUsage.DigitalSignature);
                    return ClientCertificateType.rsa_sign;
                }

                /*
                 * DSA public key; the certificate MUST allow the key to be used for signing with the
                 * hash algorithm that will be employed in the certificate verify message.
                 */
                if (publicKey is DsaPublicKeyParameters)
                {
                    ValidateKeyUsage(x509Cert, KeyUsage.DigitalSignature);
                    return ClientCertificateType.dss_sign;
                }

                /*
                 * ECDSA-capable public key; the certificate MUST allow the key to be used for signing
                 * with the hash algorithm that will be employed in the certificate verify message; the
                 * public key MUST use a curve and point format supported by the server.
                 */
                if (publicKey is ECPublicKeyParameters)
                {
                    ValidateKeyUsage(x509Cert, KeyUsage.DigitalSignature);
                    // TODO Check the curve and point format
                    return ClientCertificateType.ecdsa_sign;
                }

                // TODO Add support for ClientCertificateType.*_fixed_*

            }
            catch 
            {
            }

            throw new TlsFatalAlert(AlertDescription.unsupported_certificate);
        }

        public static bool HasSigningCapability(ClientCertificateType clientCertificateType)
        {
            switch (clientCertificateType)
            {
                case ClientCertificateType.dss_sign:
                case ClientCertificateType.ecdsa_sign:
                case ClientCertificateType.rsa_sign:
                    return true;
                default:
                    return false;
            }
        }

        public static TlsSigner CreateTlsSigner(ClientCertificateType clientCertificateType)
        {
            switch (clientCertificateType)
            {
                case ClientCertificateType.dss_sign:
                    return new TlsDssSigner();
                case ClientCertificateType.ecdsa_sign:
                    return new TlsECDsaSigner();
                case ClientCertificateType.rsa_sign:
                    return new TlsRsaSigner();
                default:
                    throw new ArgumentException("'clientCertificateType' is not a type with signing capability");
            }
        }

        internal static readonly byte[] SSL_CLIENT = { 0x43, 0x4C, 0x4E, 0x54 };
        internal static readonly byte[] SSL_SERVER = { 0x53, 0x52, 0x56, 0x52 };

        // SSL3 magic mix constants ("A", "BB", "CCC", ...)
        static readonly byte[][] SSL3_CONST = GenConst();

        private static byte[][] GenConst()
        {
            int n = 10;
            byte[][] arr = new byte[n][];
            for (int i = 0; i < n; i++)
            {
                byte[] b = new byte[i + 1];
                Arrays.Fill(b, (byte)('A' + i));
                arr[i] = b;
            }
            return arr;
        }
    }
}