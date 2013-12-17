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

        public static void CheckUint16(int i)
        {
            if (!IsValidUint16(i))
                throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        public static void CheckUint24(int i)
        {
            if (!IsValidUint24(i))
                throw new TlsFatalAlert(AlertDescription.internal_error);
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

        internal static void WriteUint8(byte i, Stream os)
        {
            os.WriteByte(i);
        }

        internal static void WriteUint8(byte i, byte[] buf, int offset)
        {
            buf[offset] = i;
        }

        internal static void WriteUint16(int i, Stream os)
        {
            os.WriteByte((byte)(i >> 8));
            os.WriteByte((byte)i);
        }

        internal static void WriteUint16(int i, byte[] buf, int offset)
        {
            buf[offset] = (byte)(i >> 8);
            buf[offset + 1] = (byte)i;
        }

        internal static void WriteUint24(int i, Stream os)
        {
            os.WriteByte((byte)(i >> 16));
            os.WriteByte((byte)(i >> 8));
            os.WriteByte((byte)i);
        }

        internal static void WriteUint24(int i, byte[] buf, int offset)
        {
            buf[offset] = (byte)(i >> 16);
            buf[offset + 1] = (byte)(i >> 8);
            buf[offset + 2] = (byte)(i);
        }

        internal static void WriteUint64(long i, Stream os)
        {
            os.WriteByte((byte)(i >> 56));
            os.WriteByte((byte)(i >> 48));
            os.WriteByte((byte)(i >> 40));
            os.WriteByte((byte)(i >> 32));
            os.WriteByte((byte)(i >> 24));
            os.WriteByte((byte)(i >> 16));
            os.WriteByte((byte)(i >> 8));
            os.WriteByte((byte)i);
        }

        internal static void WriteUint64(long i, byte[] buf, int offset)
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

        internal static void WriteOpaque8(byte[] buf, Stream os)
        {
            WriteUint8((byte)buf.Length, os);
            os.Write(buf, 0, buf.Length);
        }

        internal static void WriteOpaque16(byte[] buf, Stream os)
        {
            WriteUint16(buf.Length, os);
            os.Write(buf, 0, buf.Length);
        }

        internal static void WriteOpaque24(byte[] buf, Stream os)
        {
            WriteUint24(buf.Length, os);
            os.Write(buf, 0, buf.Length);
        }

        internal static void WriteUint8Array(byte[] uints, Stream os)
        {
            os.Write(uints, 0, uints.Length);
        }

        public static void WriteUint8ArrayWithUint8Length(byte[] uints, Stream output)
        {
            CheckUint8(uints.Length);
            WriteUint8((byte)uints.Length, output);
            WriteUint8Array(uints, output);
        }

        internal static void WriteUint16Array(int[] uints, Stream os)
        {
            for (int i = 0; i < uints.Length; ++i)
            {
                WriteUint16(uints[i], os);
            }
        }

        internal static byte ReadUint8(Stream inStr)
        {
            int i = inStr.ReadByte();
            if (i < 0)
            {
                throw new EndOfStreamException();
            }
            return (byte)i;
        }

        internal static int ReadUint16(Stream inStr)
        {
            int i1 = inStr.ReadByte();
            int i2 = inStr.ReadByte();
            if ((i1 | i2) < 0)
            {
                throw new EndOfStreamException();
            }
            return i1 << 8 | i2;
        }

        internal static int ReadUint24(Stream inStr)
        {
            int i1 = inStr.ReadByte();
            int i2 = inStr.ReadByte();
            int i3 = inStr.ReadByte();
            if ((i1 | i2 | i3) < 0)
            {
                throw new EndOfStreamException();
            }
            return (i1 << 16) | (i2 << 8) | i3;
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

        internal static void ReadFully(byte[] buf, Stream inStr)
        {
            if (Streams.ReadFully(inStr, buf, 0, buf.Length) < buf.Length)
                throw new EndOfStreamException();
        }

        internal static byte[] ReadOpaque8(Stream inStr)
        {
            byte length = ReadUint8(inStr);
            byte[] bytes = new byte[length];
            ReadFully(bytes, inStr);
            return bytes;
        }

        internal static byte[] ReadOpaque16(Stream inStr)
        {
            int length = ReadUint16(inStr);
            byte[] bytes = new byte[length];
            ReadFully(bytes, inStr);
            return bytes;
        }

        public static byte[] ReadOpaque24(Stream input)
        {
            int length = ReadUint24(input);
            return ReadFully(length, input);
        }

        internal static void CheckVersion(byte[] readVersion)
        {
            if ((readVersion[0] != 3) || (readVersion[1] != 1))
            {
                throw new TlsFatalAlert(AlertDescription.protocol_version);
            }
        }

        internal static void CheckVersion(Stream inStr)
        {
            int i1 = inStr.ReadByte();
            int i2 = inStr.ReadByte();
            if ((i1 != 3) || (i2 != 1))
            {
                throw new TlsFatalAlert(AlertDescription.protocol_version);
            }
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

        internal static void WriteGmtUnixTime(byte[] buf, int offset)
        {
            int t = (int)(DateTimeUtilities.CurrentUnixMs() / 1000L);
            buf[offset] = (byte)(t >> 24);
            buf[offset + 1] = (byte)(t >> 16);
            buf[offset + 2] = (byte)(t >> 8);
            buf[offset + 3] = (byte)t;
        }

        internal static void WriteVersion(Stream os)
        {
            os.WriteByte(3);
            os.WriteByte(1);
        }

        internal static void WriteVersion(byte[] buf, int offset)
        {
            buf[offset] = 3;
            buf[offset + 1] = 1;
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

        private static void hmac_hash(IDigest digest, byte[] secret, byte[] seed, byte[] output)
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
                Array.Copy(buf2, 0, output, (size * i), System.Math.Min(size, output.Length - (size * i)));
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
            hmac_hash(new MD5Digest(), s1, ls, prf);
            hmac_hash(new Sha1Digest(), s2, ls, buf);
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
            hmac_hash(digest, secret, labelSeed, buf);
            return buf;
        }

        internal static byte[] Concat(byte[] a, byte[] b)
        {
            byte[] c = new byte[a.Length + b.Length];
            Array.Copy(a, 0, c, 0, a.Length);
            Array.Copy(b, 0, c, a.Length, b.Length);
            return c;
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
    }
}
