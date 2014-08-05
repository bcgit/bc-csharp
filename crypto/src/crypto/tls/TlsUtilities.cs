using System;
using System.Collections;
using System.IO;
using System.Text;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Date;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Crypto.Tls
{
    /// <remarks>Some helper functions for MicroTLS.</remarks>
    public class TlsUtilities
    {
        public static readonly byte[] EmptyBytes = new byte[0];

        public static void CheckUint8(int i)
        {
            if (!IsValidUint8(i))
                throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        public static void CheckUint8(long i)
        {
            if (!IsValidUint8(i))
                throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        public static void CheckUint16(int i)
        {
            if (!IsValidUint16(i))
                throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        public static void CheckUint16(long i)
        {
            if (!IsValidUint16(i))
                throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        public static void CheckUint24(int i)
        {
            if (!IsValidUint24(i))
                throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        public static void CheckUint24(long i)
        {
            if (!IsValidUint24(i))
                throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        public static void CheckUint32(long i)
        {
            if (!IsValidUint32(i))
                throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        public static void CheckUint48(long i)
        {
            if (!IsValidUint48(i))
                throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        public static void CheckUint64(long i)
        {
            if (!IsValidUint64(i))
                throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        public static bool IsValidUint8(int i)
        {
            return (i & 0xFF) == i;
        }

        public static bool IsValidUint8(long i)
        {
            return (i & 0xFFL) == i;
        }

        public static bool IsValidUint16(int i)
        {
            return (i & 0xFFFF) == i;
        }

        public static bool IsValidUint16(long i)
        {
            return (i & 0xFFFFL) == i;
        }

        public static bool IsValidUint24(int i)
        {
            return (i & 0xFFFFFF) == i;
        }

        public static bool IsValidUint24(long i)
        {
            return (i & 0xFFFFFFL) == i;
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

        public static bool IsSsl(TlsContext context)
        {
            return context.ServerVersion.IsSsl;
        }

        public static bool IsTlsV11(TlsContext context)
        {
            return ProtocolVersion.TLSv11.IsEqualOrEarlierVersionOf(context.ServerVersion.GetEquivalentTLSVersion());
        }

        public static bool IsTlsV12(TlsContext context)
        {
            return ProtocolVersion.TLSv12.IsEqualOrEarlierVersionOf(context.ServerVersion.GetEquivalentTLSVersion());
        }

        public static void WriteUint8(byte i, Stream output)
        {
            output.WriteByte(i);
        }

        public static void WriteUint8(byte i, byte[] buf, int offset)
        {
            buf[offset] = i;
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
            buf[offset + 2] = (byte)i;
        }

        public static void WriteUint32(long i, Stream output)
        {
            output.WriteByte((byte)(i >> 24));
            output.WriteByte((byte)(i >> 16));
            output.WriteByte((byte)(i >> 8));
            output.WriteByte((byte)i);
        }

        public static void WriteUint32(long i, byte[] buf, int offset)
        {
            buf[offset] = (byte)(i >> 24);
            buf[offset + 1] = (byte)(i >> 16);
            buf[offset + 2] = (byte)(i >> 8);
            buf[offset + 3] = (byte)i;
        }

        public static void WriteUint48(long i, Stream output)
        {
            output.WriteByte((byte)(i >> 40));
            output.WriteByte((byte)(i >> 32));
            output.WriteByte((byte)(i >> 24));
            output.WriteByte((byte)(i >> 16));
            output.WriteByte((byte)(i >> 8));
            output.WriteByte((byte)i);
        }

        public static void WriteUint48(long i, byte[] buf, int offset)
        {
            buf[offset] = (byte)(i >> 40);
            buf[offset + 1] = (byte)(i >> 32);
            buf[offset + 2] = (byte)(i >> 24);
            buf[offset + 3] = (byte)(i >> 16);
            buf[offset + 4] = (byte)(i >> 8);
            buf[offset + 5] = (byte)i;
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
            output.WriteByte((byte)i);
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
            buf[offset + 7] = (byte)i;
        }

        public static void WriteOpaque8(byte[] buf, Stream output)
        {
            WriteUint8((byte)buf.Length, output);
            output.Write(buf, 0, buf.Length);
        }

        public static void WriteOpaque16(byte[] buf, Stream output)
        {
            WriteUint16(buf.Length, output);
            output.Write(buf, 0, buf.Length);
        }

        public static void WriteOpaque24(byte[] buf, Stream output)
        {
            WriteUint24(buf.Length, output);
            output.Write(buf, 0, buf.Length);
        }

        public static void WriteUint8Array(byte[] uints, Stream output)
        {
            output.Write(uints, 0, uints.Length);
        }

        public static void WriteUint8Array(byte[] uints, byte[] buf, int offset)
        {
            for (int i = 0; i < uints.Length; ++i)
            {
                WriteUint8(uints[i], buf, offset);
                ++offset;
            }
        }

        public static void WriteUint8ArrayWithUint8Length(byte[] uints, Stream output)
        {
            CheckUint8(uints.Length);
            WriteUint8((byte)uints.Length, output);
            WriteUint8Array(uints, output);
        }

        public static void WriteUint8ArrayWithUint8Length(byte[] uints, byte[] buf, int offset)
        {
            CheckUint8(uints.Length);
            WriteUint8((byte)uints.Length, buf, offset);
            WriteUint8Array(uints, buf, offset + 1);
        }

        public static void WriteUint16Array(int[] uints, Stream output)
        {
            for (int i = 0; i < uints.Length; ++i)
            {
                WriteUint16(uints[i], output);
            }
        }

        public static void WriteUint16Array(int[] uints, byte[] buf, int offset)
        {
            for (int i = 0; i < uints.Length; ++i)
            {
                WriteUint16(uints[i], buf, offset);
                offset += 2;
            }
        }

        public static void WriteUint16ArrayWithUint16Length(int[] uints, Stream output)
        {
            int length = 2 * uints.Length;
            CheckUint16(length);
            WriteUint16(length, output);
            WriteUint16Array(uints, output);
        }

        public static void WriteUint16ArrayWithUint16Length(int[] uints, byte[] buf, int offset)
        {
            int length = 2 * uints.Length;
            CheckUint16(length);
            WriteUint16(length, buf, offset);
            WriteUint16Array(uints, buf, offset + 2);
        }

        public static byte[] EncodeOpaque8(byte[] buf)
        {
            CheckUint8(buf.Length);
            return Arrays.Prepend(buf, (byte)buf.Length);
        }

        public static byte[] EncodeUint8ArrayWithUint8Length(byte[] uints)
        {
            byte[] result = new byte[1 + uints.Length];
            WriteUint8ArrayWithUint8Length(uints, result, 0);
            return result;
        }

        public static byte[] EncodeUint16ArrayWithUint16Length(int[] uints)
        {
            int length = 2 * uints.Length;
            byte[] result = new byte[2 + length];
            WriteUint16ArrayWithUint16Length(uints, result, 0);
            return result;
        }

        public static byte ReadUint8(Stream input)
        {
            int i = input.ReadByte();
            if (i < 0)
            {
                throw new EndOfStreamException();
            }
            return (byte)i;
        }

        public static byte ReadUint8(byte[] buf, int offset)
        {
            return buf[offset];
        }

        public static int ReadUint16(Stream input)
        {
            int i1 = input.ReadByte();
            int i2 = input.ReadByte();
            if ((i1 | i2) < 0)
            {
                throw new EndOfStreamException();
            }
            return i1 << 8 | i2;
        }

        public static int ReadUint16(byte[] buf, int offset)
        {
            uint n = (uint)buf[offset] << 8;
            n |= (uint)buf[++offset];
            return (int)n;
        }

        public static int ReadUint24(Stream input)
        {
            int i1 = input.ReadByte();
            int i2 = input.ReadByte();
            int i3 = input.ReadByte();
            if ((i1 | i2 | i3) < 0)
            {
                throw new EndOfStreamException();
            }
            return (i1 << 16) | (i2 << 8) | i3;
        }

        public static int ReadUint24(byte[] buf, int offset)
        {
            uint n = (uint)buf[offset] << 16;
            n |= (uint)buf[++offset] << 8;
            n |= (uint)buf[++offset];
            return (int)n;
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
            return (long)(uint)((i1 << 24) | (i2 << 16) | (i3 << 8) | i4);
        }

        public static long ReadUint32(byte[] buf, int offset)
        {
            uint n = (uint)buf[offset] << 24;
            n |= (uint)buf[++offset] << 16;
            n |= (uint)buf[++offset] << 8;
            n |= (uint)buf[++offset];
            return (long)n;
        }

        public static long ReadUint48(Stream input)
        {
            int hi = ReadUint24(input);
            int lo = ReadUint24(input);
            return ((long)(hi & 0xffffffffL) << 24) | (long)(lo & 0xffffffffL);
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
                return EmptyBytes;
            byte[] buf = new byte[length];
            int read = Streams.ReadFully(input, buf);
            if (read == 0)
                return null;
            if (read != length)
                throw new EndOfStreamException();
            return buf;
        }

        public static byte[] ReadFully(int length, Stream input)
        {
            if (length < 1)
                return EmptyBytes;
            byte[] buf = new byte[length];
            if (length != Streams.ReadFully(input, buf))
                throw new EndOfStreamException();
            return buf;
        }

        public static void ReadFully(byte[] buf, Stream input)
        {
            if (Streams.ReadFully(input, buf, 0, buf.Length) < buf.Length)
                throw new EndOfStreamException();
        }

        public static byte[] ReadOpaque8(Stream input)
        {
            byte length = ReadUint8(input);
            byte[] bytes = new byte[length];
            ReadFully(bytes, input);
            return bytes;
        }

        public static byte[] ReadOpaque16(Stream input)
        {
            int length = ReadUint16(input);
            byte[] bytes = new byte[length];
            ReadFully(bytes, input);
            return bytes;
        }

        public static byte[] ReadOpaque24(Stream input)
        {
            int length = ReadUint24(input);
            return ReadFully(length, input);
        }

        public static byte[] ReadUint8Array(int count, Stream input)
        {
            byte[] uints = new byte[count];
            for (int i = 0; i < count; ++i)
            {
                uints[i] = ReadUint8(input);
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

        [Obsolete]
        public static void CheckVersion(byte[] ReadVersion)
        {
            if ((ReadVersion[0] != 3) || (ReadVersion[1] != 1))
            {
                throw new TlsFatalAlert(AlertDescription.protocol_version);
            }
        }

        [Obsolete]
        public static void CheckVersion(Stream input)
        {
            int i1 = input.ReadByte();
            int i2 = input.ReadByte();
            if ((i1 != 3) || (i2 != 1))
            {
                throw new TlsFatalAlert(AlertDescription.protocol_version);
            }
        }

        public static ProtocolVersion ReadVersion(byte[] buf, int offset)
        {
            return ProtocolVersion.Get(buf[offset], buf[offset + 1]);
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
            Asn1Object result = asn1.ReadObject();
            if (null == result)
                throw new TlsFatalAlert(AlertDescription.decode_error);
            if (null != asn1.ReadObject())
                throw new TlsFatalAlert(AlertDescription.decode_error);
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
                throw new TlsFatalAlert(AlertDescription.decode_error);
            return result;
        }

        public static void WriteGmtUnixTime(byte[] buf, int offset)
        {
            int t = (int)(DateTimeUtilities.CurrentUnixMs() / 1000L);
            buf[offset] = (byte)(t >> 24);
            buf[offset + 1] = (byte)(t >> 16);
            buf[offset + 2] = (byte)(t >> 8);
            buf[offset + 3] = (byte)t;
        }

        [Obsolete]
        public static void WriteVersion(Stream output)
        {
            output.WriteByte(3);
            output.WriteByte(1);
        }

        [Obsolete]
        public static void WriteVersion(byte[] buf, int offset)
        {
            buf[offset] = 3;
            buf[offset + 1] = 1;
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

        public static IList GetDefaultDssSignatureAlgorithms()
        {
            return VectorOfOne(new SignatureAndHashAlgorithm(HashAlgorithm.sha1, SignatureAlgorithm.dsa));
        }

        public static IList GetDefaultECDsaSignatureAlgorithms()
        {
            return VectorOfOne(new SignatureAndHashAlgorithm(HashAlgorithm.sha1, SignatureAlgorithm.ecdsa));
        }

        public static IList GetDefaultRsaSignatureAlgorithms()
        {
            return VectorOfOne(new SignatureAndHashAlgorithm(HashAlgorithm.sha1, SignatureAlgorithm.rsa));
        }

        public static byte[] GetExtensionData(IDictionary extensions, int extensionType)
        {
            return extensions == null ? null : (byte[])extensions[extensionType];
        }

        public static bool HasExpectedEmptyExtensionData(IDictionary extensions, int extensionType,
            byte alertDescription)
        {
            byte[] extension_data = GetExtensionData(extensions, extensionType);
            if (extension_data == null)
                return false;
            if (extension_data.Length != 0)
                throw new TlsFatalAlert(alertDescription);
            return true;
        }

        public static void EncodeSupportedSignatureAlgorithms(IList supportedSignatureAlgorithms, bool allowAnonymous,
            Stream output)
        {
            if (supportedSignatureAlgorithms == null || supportedSignatureAlgorithms.Count < 1
                || supportedSignatureAlgorithms.Count >= (1 << 15))
            {
                throw new ArgumentException("must have length from 1 to (2^15 - 1)", "supportedSignatureAlgorithms");
            }

            // supported_signature_algorithms
            int length = 2 * supportedSignatureAlgorithms.Count;
            TlsUtilities.CheckUint16(length);
            TlsUtilities.WriteUint16(length, output);

            foreach (SignatureAndHashAlgorithm entry in supportedSignatureAlgorithms)
            {
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

        internal static byte[] PRF(byte[] secret, string asciiLabel, byte[] seed, int size)
        {
            byte[] label = Strings.ToAsciiByteArray(asciiLabel);

            int s_half = (secret.Length + 1) / 2;
            byte[] s1 = new byte[s_half];
            byte[] s2 = new byte[s_half];
            Array.Copy(secret, 0, s1, 0, s_half);
            Array.Copy(secret, secret.Length - s_half, s2, 0, s_half);

            byte[] ls = Concat(label, seed);

            byte[] buf = new byte[size];
            byte[] prf = new byte[size];
            HMacHash(new MD5Digest(), s1, ls, prf);
            HMacHash(new Sha1Digest(), s2, ls, buf);
            for (int i = 0; i < size; i++)
            {
                buf[i] ^= prf[i];
            }
            return buf;
        }

        internal static byte[] PRF_1_2(IDigest digest, byte[] secret, string asciiLabel, byte[] seed, int size)
        {
            byte[] label = Strings.ToAsciiByteArray(asciiLabel);
            byte[] labelSeed = Concat(label, seed);

            byte[] buf = new byte[size];
            HMacHash(digest, secret, labelSeed, buf);
            return buf;
        }

        internal static byte[] Concat(byte[] a, byte[] b)
        {
            byte[] c = new byte[a.Length + b.Length];
            Array.Copy(a, 0, c, 0, a.Length);
            Array.Copy(b, 0, c, a.Length, b.Length);
            return c;
        }

        internal static void HMacHash(IDigest digest, byte[] secret, byte[] seed, byte[] output)
        {
            HMac mac = new HMac(digest);
            mac.Init(new KeyParameter(secret));
            byte[] a = seed;
            int size = digest.GetDigestSize();
            int iterations = (output.Length + size - 1) / size;
            byte[] buf = new byte[mac.GetMacSize()];
            byte[] buf2 = new byte[mac.GetMacSize()];
            for (int i = 0; i < iterations; i++)
            {
                mac.BlockUpdate(a, 0, a.Length);
                mac.DoFinal(buf, 0);
                a = buf;
                mac.BlockUpdate(a, 0, a.Length);
                mac.BlockUpdate(seed, 0, seed.Length);
                mac.DoFinal(buf2, 0);
                Array.Copy(buf2, 0, output, (size * i), System.Math.Min(size, output.Length - (size * i)));
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

        public static IDigest CreateHash(byte hashAlgorithm)
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
                throw new ArgumentException("unknown HashAlgorithm", "hashAlgorithm");
            }
        }

        public static IDigest CloneHash(byte hashAlgorithm, IDigest hash)
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
                throw new ArgumentException("unknown HashAlgorithm", "hashAlgorithm");
            }
        }

        private static IList VectorOfOne(object obj)
        {
            IList v = Platform.CreateArrayList(1);
            v.Add(obj);
            return v;
        }

        public static int GetCipherType(int ciphersuite)
        {
            switch (GetEncryptionAlgorithm(ciphersuite))
            {
            case EncryptionAlgorithm.AES_128_GCM:
            case EncryptionAlgorithm.AES_256_GCM:
            case EncryptionAlgorithm.AES_128_CCM:
            case EncryptionAlgorithm.AES_128_CCM_8:
            case EncryptionAlgorithm.AES_256_CCM:
            case EncryptionAlgorithm.AES_256_CCM_8:
            case EncryptionAlgorithm.CAMELLIA_128_GCM:
            case EncryptionAlgorithm.CAMELLIA_256_GCM:
            case EncryptionAlgorithm.AEAD_CHACHA20_POLY1305:
                return CipherType.aead;

            case EncryptionAlgorithm.RC2_CBC_40:
            case EncryptionAlgorithm.IDEA_CBC:
            case EncryptionAlgorithm.DES40_CBC:
            case EncryptionAlgorithm.DES_CBC:
            case EncryptionAlgorithm.cls_3DES_EDE_CBC:
            case EncryptionAlgorithm.AES_128_CBC:
            case EncryptionAlgorithm.AES_256_CBC:
            case EncryptionAlgorithm.CAMELLIA_128_CBC:
            case EncryptionAlgorithm.CAMELLIA_256_CBC:
            case EncryptionAlgorithm.SEED_CBC:
                return CipherType.block;

            case EncryptionAlgorithm.RC4_40:
            case EncryptionAlgorithm.RC4_128:
            case EncryptionAlgorithm.ESTREAM_SALSA20:
            case EncryptionAlgorithm.SALSA20:
                return CipherType.stream;

            default:
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }
        }

        public static int GetEncryptionAlgorithm(int ciphersuite)
        {
            switch (ciphersuite)
            {
            case CipherSuite.TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA:
            case CipherSuite.TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA:
            case CipherSuite.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA:
            case CipherSuite.TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA:
            case CipherSuite.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA:
            case CipherSuite.TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA:
            case CipherSuite.TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA:
            case CipherSuite.TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA:
            case CipherSuite.TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA:
            case CipherSuite.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:
            case CipherSuite.TLS_PSK_WITH_3DES_EDE_CBC_SHA:
            case CipherSuite.TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA:
            case CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA:
            case CipherSuite.TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA:
            case CipherSuite.TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA:
            case CipherSuite.TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA:
                return EncryptionAlgorithm.cls_3DES_EDE_CBC;

            case CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
            case CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
            case CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
                return EncryptionAlgorithm.AEAD_CHACHA20_POLY1305;

            case CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA:
            case CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA:
            case CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA:
            case CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA:
            case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA:
            case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA:
            case CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA:
            case CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA:
            case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
            case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
            case CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA:
            case CipherSuite.TLS_RSA_PSK_WITH_AES_128_CBC_SHA:
            case CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA:
            case CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA:
            case CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA:
            case CipherSuite.TLS_SRP_SHA_WITH_AES_128_CBC_SHA:
                return EncryptionAlgorithm.AES_128_CBC;

            case CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA256:
            case CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA256:
            case CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256:
            case CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA256:
            case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256:
            case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256:
            case CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256:
            case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
            case CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256:
            case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
            case CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256:
            case CipherSuite.TLS_RSA_PSK_WITH_AES_128_CBC_SHA256:
            case CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256:
                return EncryptionAlgorithm.AES_128_CBC;

            case CipherSuite.TLS_DHE_PSK_WITH_AES_128_CCM:
            case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM:
            case CipherSuite.TLS_PSK_WITH_AES_128_CCM:
            case CipherSuite.TLS_RSA_WITH_AES_128_CCM:
                return EncryptionAlgorithm.AES_128_CCM;

            case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM_8:
            case CipherSuite.TLS_PSK_DHE_WITH_AES_128_CCM_8:
            case CipherSuite.TLS_PSK_WITH_AES_128_CCM_8:
            case CipherSuite.TLS_RSA_WITH_AES_128_CCM_8:
                return EncryptionAlgorithm.AES_128_CCM_8;

            case CipherSuite.TLS_DH_DSS_WITH_AES_128_GCM_SHA256:
            case CipherSuite.TLS_DH_RSA_WITH_AES_128_GCM_SHA256:
            case CipherSuite.TLS_DHE_DSS_WITH_AES_128_GCM_SHA256:
            case CipherSuite.TLS_DHE_PSK_WITH_AES_128_GCM_SHA256:
            case CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256:
            case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256:
            case CipherSuite.TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256:
            case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
            case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
            case CipherSuite.TLS_PSK_WITH_AES_128_GCM_SHA256:
            case CipherSuite.TLS_RSA_PSK_WITH_AES_128_GCM_SHA256:
            case CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256:
                return EncryptionAlgorithm.AES_128_GCM;

            case CipherSuite.TLS_DH_DSS_WITH_AES_256_CBC_SHA:
            case CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA:
            case CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA:
            case CipherSuite.TLS_DHE_PSK_WITH_AES_256_CBC_SHA:
            case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA:
            case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA:
            case CipherSuite.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA:
            case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
            case CipherSuite.TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA:
            case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
            case CipherSuite.TLS_PSK_WITH_AES_256_CBC_SHA:
            case CipherSuite.TLS_RSA_PSK_WITH_AES_256_CBC_SHA:
            case CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA:
            case CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA:
            case CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA:
            case CipherSuite.TLS_SRP_SHA_WITH_AES_256_CBC_SHA:
                return EncryptionAlgorithm.AES_256_CBC;

            case CipherSuite.TLS_DH_DSS_WITH_AES_256_CBC_SHA256:
            case CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA256:
            case CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA256:
            case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256:
            case CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256:
                return EncryptionAlgorithm.AES_256_CBC;

            case CipherSuite.TLS_DHE_PSK_WITH_AES_256_CBC_SHA384:
            case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384:
            case CipherSuite.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384:
            case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384:
            case CipherSuite.TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384:
            case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384:
            case CipherSuite.TLS_PSK_WITH_AES_256_CBC_SHA384:
            case CipherSuite.TLS_RSA_PSK_WITH_AES_256_CBC_SHA384:
                return EncryptionAlgorithm.AES_256_CBC;

            case CipherSuite.TLS_DHE_PSK_WITH_AES_256_CCM:
            case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM:
            case CipherSuite.TLS_PSK_WITH_AES_256_CCM:
            case CipherSuite.TLS_RSA_WITH_AES_256_CCM:
                return EncryptionAlgorithm.AES_256_CCM;

            case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM_8:
            case CipherSuite.TLS_PSK_DHE_WITH_AES_256_CCM_8:
            case CipherSuite.TLS_PSK_WITH_AES_256_CCM_8:
            case CipherSuite.TLS_RSA_WITH_AES_256_CCM_8:
                return EncryptionAlgorithm.AES_256_CCM_8;

            case CipherSuite.TLS_DH_DSS_WITH_AES_256_GCM_SHA384:
            case CipherSuite.TLS_DH_RSA_WITH_AES_256_GCM_SHA384:
            case CipherSuite.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384:
            case CipherSuite.TLS_DHE_PSK_WITH_AES_256_GCM_SHA384:
            case CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384:
            case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384:
            case CipherSuite.TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384:
            case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
            case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
            case CipherSuite.TLS_PSK_WITH_AES_256_GCM_SHA384:
            case CipherSuite.TLS_RSA_PSK_WITH_AES_256_GCM_SHA384:
            case CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384:
                return EncryptionAlgorithm.AES_256_GCM;

            case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA:
            case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA:
            case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA:
            case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA:
            case CipherSuite.TLS_RSA_WITH_CAMELLIA_128_CBC_SHA:
                return EncryptionAlgorithm.CAMELLIA_128_CBC;

            case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256:
            case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256:
            case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256:
            case CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256:
            case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256:
            case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256:
            case CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256:
            case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256:
            case CipherSuite.TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256:
            case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256:
            case CipherSuite.TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256:
            case CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256:
            case CipherSuite.TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256:
                return EncryptionAlgorithm.CAMELLIA_128_CBC;

            case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256:
            case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256:
            case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256:
            case CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256:
            case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256:
            case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256:
            case CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256:
            case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256:
            case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256:
            case CipherSuite.TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256:
            case CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256:
            case CipherSuite.TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256:
                return EncryptionAlgorithm.CAMELLIA_128_GCM;

            case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA:
            case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA:
            case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA:
            case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA:
            case CipherSuite.TLS_RSA_WITH_CAMELLIA_256_CBC_SHA:
                return EncryptionAlgorithm.CAMELLIA_256_CBC;

            case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256:
            case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256:
            case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256:
            case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256:
            case CipherSuite.TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256:
                return EncryptionAlgorithm.CAMELLIA_256_CBC;

            case CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384:
            case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384:
            case CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384:
            case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384:
            case CipherSuite.TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384:
            case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384:
            case CipherSuite.TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384:
            case CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384:
                return EncryptionAlgorithm.CAMELLIA_256_CBC;

            case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384:
            case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384:
            case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384:
            case CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384:
            case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384:
            case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384:
            case CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384:
            case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384:
            case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384:
            case CipherSuite.TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384:
            case CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384:
            case CipherSuite.TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384:
                return EncryptionAlgorithm.CAMELLIA_256_GCM;

            case CipherSuite.TLS_DHE_PSK_WITH_ESTREAM_SALSA20_SHA1:
            case CipherSuite.TLS_DHE_RSA_WITH_ESTREAM_SALSA20_SHA1:
            case CipherSuite.TLS_ECDHE_ECDSA_WITH_ESTREAM_SALSA20_SHA1:
            case CipherSuite.TLS_ECDHE_PSK_WITH_ESTREAM_SALSA20_SHA1:
            case CipherSuite.TLS_ECDHE_RSA_WITH_ESTREAM_SALSA20_SHA1:
            case CipherSuite.TLS_PSK_WITH_ESTREAM_SALSA20_SHA1:
            case CipherSuite.TLS_RSA_PSK_WITH_ESTREAM_SALSA20_SHA1:
            case CipherSuite.TLS_RSA_WITH_ESTREAM_SALSA20_SHA1:
                return EncryptionAlgorithm.ESTREAM_SALSA20;

            case CipherSuite.TLS_RSA_WITH_NULL_MD5:
                return EncryptionAlgorithm.NULL;

            case CipherSuite.TLS_DHE_PSK_WITH_NULL_SHA:
            case CipherSuite.TLS_ECDH_ECDSA_WITH_NULL_SHA:
            case CipherSuite.TLS_ECDH_RSA_WITH_NULL_SHA:
            case CipherSuite.TLS_ECDHE_ECDSA_WITH_NULL_SHA:
            case CipherSuite.TLS_ECDHE_PSK_WITH_NULL_SHA:
            case CipherSuite.TLS_ECDHE_RSA_WITH_NULL_SHA:
            case CipherSuite.TLS_PSK_WITH_NULL_SHA:
            case CipherSuite.TLS_RSA_PSK_WITH_NULL_SHA:
            case CipherSuite.TLS_RSA_WITH_NULL_SHA:
                return EncryptionAlgorithm.NULL;

            case CipherSuite.TLS_DHE_PSK_WITH_NULL_SHA256:
            case CipherSuite.TLS_ECDHE_PSK_WITH_NULL_SHA256:
            case CipherSuite.TLS_PSK_WITH_NULL_SHA256:
            case CipherSuite.TLS_RSA_PSK_WITH_NULL_SHA256:
            case CipherSuite.TLS_RSA_WITH_NULL_SHA256:
                return EncryptionAlgorithm.NULL;

            case CipherSuite.TLS_DHE_PSK_WITH_NULL_SHA384:
            case CipherSuite.TLS_ECDHE_PSK_WITH_NULL_SHA384:
            case CipherSuite.TLS_PSK_WITH_NULL_SHA384:
            case CipherSuite.TLS_RSA_PSK_WITH_NULL_SHA384:
                return EncryptionAlgorithm.NULL;

            case CipherSuite.TLS_DH_anon_WITH_RC4_128_MD5:
            case CipherSuite.TLS_RSA_WITH_RC4_128_MD5:
                return EncryptionAlgorithm.RC4_128;

            case CipherSuite.TLS_DHE_PSK_WITH_RC4_128_SHA:
            case CipherSuite.TLS_ECDH_anon_WITH_RC4_128_SHA:
            case CipherSuite.TLS_ECDH_ECDSA_WITH_RC4_128_SHA:
            case CipherSuite.TLS_ECDH_RSA_WITH_RC4_128_SHA:
            case CipherSuite.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:
            case CipherSuite.TLS_ECDHE_PSK_WITH_RC4_128_SHA:
            case CipherSuite.TLS_ECDHE_RSA_WITH_RC4_128_SHA:
            case CipherSuite.TLS_PSK_WITH_RC4_128_SHA:
            case CipherSuite.TLS_RSA_WITH_RC4_128_SHA:
            case CipherSuite.TLS_RSA_PSK_WITH_RC4_128_SHA:
                return EncryptionAlgorithm.RC4_128;

            case CipherSuite.TLS_DHE_PSK_WITH_SALSA20_SHA1:
            case CipherSuite.TLS_DHE_RSA_WITH_SALSA20_SHA1:
            case CipherSuite.TLS_ECDHE_ECDSA_WITH_SALSA20_SHA1:
            case CipherSuite.TLS_ECDHE_PSK_WITH_SALSA20_SHA1:
            case CipherSuite.TLS_ECDHE_RSA_WITH_SALSA20_SHA1:
            case CipherSuite.TLS_PSK_WITH_SALSA20_SHA1:
            case CipherSuite.TLS_RSA_PSK_WITH_SALSA20_SHA1:
            case CipherSuite.TLS_RSA_WITH_SALSA20_SHA1:
                return EncryptionAlgorithm.SALSA20;

            case CipherSuite.TLS_DH_DSS_WITH_SEED_CBC_SHA:
            case CipherSuite.TLS_DH_RSA_WITH_SEED_CBC_SHA:
            case CipherSuite.TLS_DHE_DSS_WITH_SEED_CBC_SHA:
            case CipherSuite.TLS_DHE_RSA_WITH_SEED_CBC_SHA:
            case CipherSuite.TLS_RSA_WITH_SEED_CBC_SHA:
                return EncryptionAlgorithm.SEED_CBC;

            default:
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }
        }

        public static ProtocolVersion GetMinimumVersion(int ciphersuite)
        {
            switch (ciphersuite)
            {
            case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256:
            case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256:
            case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256:
            case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384:
            case CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA256:
            case CipherSuite.TLS_DH_DSS_WITH_AES_128_GCM_SHA256:
            case CipherSuite.TLS_DH_DSS_WITH_AES_256_CBC_SHA256:
            case CipherSuite.TLS_DH_DSS_WITH_AES_256_GCM_SHA384:
            case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256:
            case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256:
            case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256:
            case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384:
            case CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA256:
            case CipherSuite.TLS_DH_RSA_WITH_AES_128_GCM_SHA256:
            case CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA256:
            case CipherSuite.TLS_DH_RSA_WITH_AES_256_GCM_SHA384:
            case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256:
            case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256:
            case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256:
            case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384:
            case CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256:
            case CipherSuite.TLS_DHE_DSS_WITH_AES_128_GCM_SHA256:
            case CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA256:
            case CipherSuite.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384:
            case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256:
            case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256:
            case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256:
            case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384:
            case CipherSuite.TLS_DHE_PSK_WITH_AES_128_CCM:
            case CipherSuite.TLS_DHE_PSK_WITH_AES_128_GCM_SHA256:
            case CipherSuite.TLS_DHE_PSK_WITH_AES_256_CCM:
            case CipherSuite.TLS_DHE_PSK_WITH_AES_256_GCM_SHA384:
            case CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256:
            case CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384:
            case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256:
            case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM:
            case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM_8:
            case CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256:
            case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256:
            case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM:
            case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM_8:
            case CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384:
            case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256:
            case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256:
            case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256:
            case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384:
            case CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
            case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256:
            case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256:
            case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384:
            case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384:
            case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256:
            case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256:
            case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384:
            case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384:
            case CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256:
            case CipherSuite.TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256:
            case CipherSuite.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384:
            case CipherSuite.TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384:
            case CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256:
            case CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256:
            case CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384:
            case CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384:
            case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
            case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
            case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384:
            case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
            case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256:
            case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256:
            case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384:
            case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384:
            case CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
            case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
            case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
            case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384:
            case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
            case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256:
            case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256:
            case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384:
            case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384:
            case CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
            case CipherSuite.TLS_PSK_DHE_WITH_AES_128_CCM_8:
            case CipherSuite.TLS_PSK_DHE_WITH_AES_256_CCM_8:
            case CipherSuite.TLS_PSK_WITH_AES_128_CCM:
            case CipherSuite.TLS_PSK_WITH_AES_128_CCM_8:
            case CipherSuite.TLS_PSK_WITH_AES_128_GCM_SHA256:
            case CipherSuite.TLS_PSK_WITH_AES_256_CCM:
            case CipherSuite.TLS_PSK_WITH_AES_256_CCM_8:
            case CipherSuite.TLS_PSK_WITH_AES_256_GCM_SHA384:
            case CipherSuite.TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256:
            case CipherSuite.TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384:
            case CipherSuite.TLS_RSA_PSK_WITH_AES_128_GCM_SHA256:
            case CipherSuite.TLS_RSA_PSK_WITH_AES_256_GCM_SHA384:
            case CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256:
            case CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384:
            case CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256:
            case CipherSuite.TLS_RSA_WITH_AES_128_CCM:
            case CipherSuite.TLS_RSA_WITH_AES_128_CCM_8:
            case CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256:
            case CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256:
            case CipherSuite.TLS_RSA_WITH_AES_256_CCM:
            case CipherSuite.TLS_RSA_WITH_AES_256_CCM_8:
            case CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384:
            case CipherSuite.TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256:
            case CipherSuite.TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256:
            case CipherSuite.TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256:
            case CipherSuite.TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384:
            case CipherSuite.TLS_RSA_WITH_NULL_SHA256:
                return ProtocolVersion.TLSv12;

            default:
                return ProtocolVersion.SSLv3;
            }
        }

        public static bool IsAeadCipherSuite(int ciphersuite)
        {
            return CipherType.aead == GetCipherType(ciphersuite);
        }

        public static bool IsBlockCipherSuite(int ciphersuite)
        {
            return CipherType.block == GetCipherType(ciphersuite);
        }

        public static bool IsStreamCipherSuite(int ciphersuite)
        {
            return CipherType.stream == GetCipherType(ciphersuite);
        }

        public static bool IsValidCipherSuiteForVersion(int cipherSuite, ProtocolVersion serverVersion)
        {
            return GetMinimumVersion(cipherSuite).IsEqualOrEarlierVersionOf(serverVersion.GetEquivalentTLSVersion());
        }
    }
}
