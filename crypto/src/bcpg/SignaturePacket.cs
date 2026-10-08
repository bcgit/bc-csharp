using System;
using System.Collections.Generic;
using System.IO;

using Org.BouncyCastle.Bcpg.Sig;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Date;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Bcpg
{
    /// <remarks>Generic signature packet.</remarks>
    public class SignaturePacket
        : ContainedPacket
    {
        public const int Version2 = 2;
        public const int Version3 = 3;
        public const int Version4 = 4;  // https://datatracker.ietf.org/doc/rfc4880/
        public const int Version5 = 5;  // https://datatracker.ietf.org/doc/draft-koch-librepgp/
        public const int Version6 = 6;  // https://www.rfc-editor.org/rfc/rfc9580.html

        private const int Ed25519SignatureLength = 64;
        private const int Ed448SignatureLength = 114;

        // RFC 9980 5.2.1 and 5.2.2
        private const int MLDsa65Ed25519SignatureLength = Ed25519SignatureLength + 3309;
        private const int MLDsa87Ed448SignatureLength = Ed448SignatureLength + 4627;
        private const int SlhDsaShake128sSignatureLength = 7856;
        private const int SlhDsaShake128fSignatureLength = 17088;
        private const int SlhDsaShake256sSignatureLength = 29792;

        private int version;
        private int signatureType;
        private long m_creationTime;
        private ulong m_keyID;
        private PublicKeyAlgorithmTag keyAlgorithm;
        private HashAlgorithmTag hashAlgorithm;
        private MPInteger[] signature;
        private byte[] fingerprint;
        private SignatureSubpacket[] hashedData;
        private SignatureSubpacket[] unhashedData;

        // The hashed subpacket area as it was read, which the signature covers (null for a packet made here)
        private byte[] m_hashedArea;
        private byte[] signatureEncoding;
        private byte[] m_salt = null; // v6 only

        // Set when the signature value could not be interpreted; such a signature never verifies.
        internal bool IsMalformed { get; private set; }

        internal void MarkMalformed() => IsMalformed = true;

        // Set when the parser repaired a subpacket that was shorter than its length said.
        internal bool HasRepairedSubpackets { get; private set; }

        // Set when an Issuer Fingerprint subpacket carries a key version that differs from the signature version.
        internal bool IssuerFingerprintVersionMismatch { get; private set; }

        internal SignaturePacket(BcpgInputStream bcpgIn)
            : this(bcpgIn, newPacketFormat: false)
        {
        }

        internal SignaturePacket(BcpgInputStream bcpgIn, bool newPacketFormat)
            : base(PacketTag.Signature, newPacketFormat)
        {
            version = bcpgIn.RequireByte();

            if (version == 3 || version == 2)
            {
                //int l =
                bcpgIn.RequireByte();

                signatureType = bcpgIn.RequireByte();
                m_creationTime = (long)StreamUtilities.RequireUInt32BE(bcpgIn) * 1000L;
                m_keyID = StreamUtilities.RequireUInt64BE(bcpgIn);
                keyAlgorithm = (PublicKeyAlgorithmTag)bcpgIn.RequireByte();
                hashAlgorithm = (HashAlgorithmTag)bcpgIn.RequireByte();
            }
            else if (version == Version4 || version == Version6)
            {
                signatureType = bcpgIn.RequireByte();
                keyAlgorithm = (PublicKeyAlgorithmTag)bcpgIn.RequireByte();
                hashAlgorithm = (HashAlgorithmTag)bcpgIn.RequireByte();

                hashedData = ReadSignatureSubpackets(bcpgIn, out m_hashedArea);

                foreach (var p in hashedData)
                {
                    if (p is IssuerKeyId issuerKeyId)
                    {
                        m_keyID = ParseKeyIdOrThrow(issuerKeyId);
                    }
                    else if (p is SignatureCreationTime signatureCreationTime)
                    {
                        m_creationTime = ParseCreationTimeOrThrow(signatureCreationTime);
                    }
                    else if (p is IssuerFingerprint issuerFingerprint && issuerFingerprint.KeyVersion != version)
                    {
                        IssuerFingerprintVersionMismatch = true;
                    }
                }

                unhashedData = ReadSignatureSubpackets(bcpgIn, out _);

                foreach (var p in unhashedData)
                {
                    if (p is IssuerKeyId issuerKeyId)
                    {
                        m_keyID = ParseKeyIdOrThrow(issuerKeyId);
                    }
                    else if (p is IssuerFingerprint issuerFingerprint && issuerFingerprint.KeyVersion != version)
                    {
                        IssuerFingerprintVersionMismatch = true;
                    }
                }

                SetIssuerKeyId();
                SetCreationTime();
            }
            else
            {
                Streams.Drain(bcpgIn);

                throw new UnsupportedPacketVersionException("unsupported version: " + version);
            }

            fingerprint = new byte[2];
            bcpgIn.ReadFully(fingerprint);

            if (version == Version6)
            {
                // RFC 9580 5.2.3: the salt length is not validated here, since it depends on the hash algorithm
                m_salt = new byte[bcpgIn.RequireByte()];
                bcpgIn.ReadFully(m_salt);
            }

            switch (keyAlgorithm)
            {
            case PublicKeyAlgorithmTag.RsaGeneral:
            case PublicKeyAlgorithmTag.RsaSign:
                MPInteger v = new MPInteger(bcpgIn);
                signature = new MPInteger[1]{ v };
                CheckMpis(bcpgIn);
                break;
            case PublicKeyAlgorithmTag.Dsa:
            case PublicKeyAlgorithmTag.ElGamalEncrypt: // yep, this really does happen sometimes.
            case PublicKeyAlgorithmTag.ElGamalGeneral:
                MPInteger r = new MPInteger(bcpgIn);
                MPInteger s = new MPInteger(bcpgIn);
                signature = new MPInteger[2]{ r, s };
                CheckMpis(bcpgIn);
                break;
            case PublicKeyAlgorithmTag.ECDsa:
            case PublicKeyAlgorithmTag.EdDsa_Legacy:
                MPInteger ecR = new MPInteger(bcpgIn);
                MPInteger ecS = new MPInteger(bcpgIn);
                signature = new MPInteger[2]{ ecR, ecS };
                CheckMpis(bcpgIn);
                break;
            case PublicKeyAlgorithmTag.Ed25519:
                // RFC 9580 5.2.3.4: 64 octets of the native signature
                ReadRawSignature(bcpgIn, Ed25519SignatureLength);
                break;
            case PublicKeyAlgorithmTag.Ed448:
                // RFC 9580 5.2.3.5: 114 octets of the native signature
                ReadRawSignature(bcpgIn, Ed448SignatureLength);
                break;
            case PublicKeyAlgorithmTag.MLDsa65_Ed25519:
                ReadRawSignature(bcpgIn, MLDsa65Ed25519SignatureLength);
                break;
            case PublicKeyAlgorithmTag.MLDsa87_Ed448:
                ReadRawSignature(bcpgIn, MLDsa87Ed448SignatureLength);
                break;
            case PublicKeyAlgorithmTag.SlhDsa_Shake128s:
                ReadRawSignature(bcpgIn, SlhDsaShake128sSignatureLength);
                break;
            case PublicKeyAlgorithmTag.SlhDsa_Shake128f:
                ReadRawSignature(bcpgIn, SlhDsaShake128fSignatureLength);
                break;
            case PublicKeyAlgorithmTag.SlhDsa_Shake256s:
                ReadRawSignature(bcpgIn, SlhDsaShake256sSignatureLength);
                break;
            default:
                // Unknown algorithms are kept opaque so that they cannot abort the parsing of a whole key ring
                signature = null;
                signatureEncoding = Streams.ReadAll(bcpgIn);
                break;
            }
        }

        /**
         * Generate a version 4 signature packet.
         *
         * @param signatureType
         * @param keyAlgorithm
         * @param hashAlgorithm
         * @param hashedData
         * @param unhashedData
         * @param fingerprint
         * @param signature
         */
        public SignaturePacket(int signatureType, long keyId, PublicKeyAlgorithmTag keyAlgorithm,
            HashAlgorithmTag hashAlgorithm, SignatureSubpacket[] hashedData, SignatureSubpacket[] unhashedData,
            byte[] fingerprint, MPInteger[] signature)
            : this(Version4, signatureType, keyId, keyAlgorithm, hashAlgorithm, hashedData, unhashedData, fingerprint,
                signature)
        {
        }

        /**
         * Generate a version 2/3 signature packet.
         *
         * @param signatureType
         * @param keyAlgorithm
         * @param hashAlgorithm
         * @param fingerprint
         * @param signature
         */
        public SignaturePacket(int version, int signatureType, long keyId, PublicKeyAlgorithmTag keyAlgorithm,
            HashAlgorithmTag hashAlgorithm, long creationTime, byte[] fingerprint, MPInteger[] signature)
            : this(version, signatureType, keyId, keyAlgorithm, hashAlgorithm, null, null, fingerprint, signature)
        {
            m_creationTime = creationTime;
        }

        public SignaturePacket(int version, int signatureType, long keyId, PublicKeyAlgorithmTag keyAlgorithm,
            HashAlgorithmTag hashAlgorithm, SignatureSubpacket[] hashedData, SignatureSubpacket[] unhashedData,
            byte[] fingerprint, MPInteger[] signature)
            : this(version, newPacketFormat: false, signatureType, keyId, keyAlgorithm, hashAlgorithm, hashedData,
                unhashedData, fingerprint, signature)
        {
        }

        public SignaturePacket(int version, bool newPacketFormat, int signatureType, long keyId,
            PublicKeyAlgorithmTag keyAlgorithm, HashAlgorithmTag hashAlgorithm, SignatureSubpacket[] hashedData,
            SignatureSubpacket[] unhashedData, byte[] fingerprint, MPInteger[] signature)
            : this(version, newPacketFormat, signatureType, keyId, keyAlgorithm, hashAlgorithm, hashedData,
                unhashedData, fingerprint, salt: null, signature, signatureEncoding: null, validate: false)
        {
        }

        /// <summary>Generate a version 4 or version 6 signature packet.</summary>
        /// <param name="salt">The signature salt; required for (and only allowed with) version 6.</param>
        /// <param name="signature">The signature value as MPIs, or null if <paramref name="signatureEncoding"/>
        /// is given.</param>
        /// <param name="signatureEncoding">The signature value as an octet string (for Ed25519, Ed448 and the
        /// RFC 9980 algorithms), or null if <paramref name="signature"/> is given.</param>
        public SignaturePacket(int version, bool newPacketFormat, int signatureType, long keyId,
            PublicKeyAlgorithmTag keyAlgorithm, HashAlgorithmTag hashAlgorithm, SignatureSubpacket[] hashedData,
            SignatureSubpacket[] unhashedData, byte[] fingerprint, byte[] salt, MPInteger[] signature,
            byte[] signatureEncoding)
            : this(version, newPacketFormat, signatureType, keyId, keyAlgorithm, hashAlgorithm, hashedData,
                unhashedData, fingerprint, salt, signature, signatureEncoding, validate: true)
        {
        }

        private SignaturePacket(int version, bool newPacketFormat, int signatureType, long keyId,
            PublicKeyAlgorithmTag keyAlgorithm, HashAlgorithmTag hashAlgorithm, SignatureSubpacket[] hashedData,
            SignatureSubpacket[] unhashedData, byte[] fingerprint, byte[] salt, MPInteger[] signature,
            byte[] signatureEncoding, bool validate)
            : base(PacketTag.Signature, newPacketFormat)
        {
            if (validate)
            {
                if ((version == Version6) != (salt != null))
                    throw new ArgumentException("a salt is required for version 6 signatures, and only for those",
                        nameof(salt));
                if ((signature != null) == (signatureEncoding != null))
                    throw new ArgumentException("exactly one of the signature forms is required", nameof(signature));
            }

            this.version = version;
            this.signatureType = signatureType;
            m_keyID = (ulong)keyId;
            this.keyAlgorithm = keyAlgorithm;
            this.hashAlgorithm = hashAlgorithm;
            this.hashedData = hashedData;
            this.unhashedData = unhashedData;
            this.fingerprint = fingerprint;

            // a packet made here is held to the same rule as a parsed one (RFC 9580 5.2.3.35)
            IssuerFingerprintVersionMismatch = HasIssuerFingerprintOfOtherVersion(hashedData) ||
                HasIssuerFingerprintOfOtherVersion(unhashedData);
            m_salt = Arrays.Clone(salt);
            this.signature = signature;
            this.signatureEncoding = signatureEncoding;

            if (hashedData != null)
            {
                SetCreationTime();
            }
        }

        /// <summary>
        /// Create a copy of <paramref name="template"/> with different subpackets, keeping its version, packet
        /// format and signature value (whether MPI-encoded or a raw octet string).
        /// </summary>
        internal SignaturePacket(SignaturePacket template, SignatureSubpacket[] hashedData,
            SignatureSubpacket[] unhashedData)
            : this(template.version, template.HasNewPacketFormat, template.signatureType, template.KeyId,
                template.keyAlgorithm, template.hashAlgorithm, hashedData, unhashedData, template.fingerprint,
                template.m_salt, template.signature, template.signatureEncoding, validate: false)
        {
            this.m_creationTime = template.m_creationTime;
            this.IsMalformed = template.IsMalformed;
            this.HasRepairedSubpackets = template.HasRepairedSubpackets;
            this.IssuerFingerprintVersionMismatch = template.IssuerFingerprintVersionMismatch;
        }

        /// <summary>
        /// A copy with other unhashed subpackets, which keeps the hashed subpacket area as it was read.
        /// </summary>
        internal SignaturePacket WithUnhashedSubpackets(SignatureSubpacket[] unhashedData)
        {
            // the new unhashed subpackets have their say on the issuer fingerprint version (RFC 9580 5.2.3.35)
            return new SignaturePacket(this, hashedData, unhashedData)
            {
                m_hashedArea = m_hashedArea,
                IssuerFingerprintVersionMismatch = HasIssuerFingerprintOfOtherVersion(hashedData) ||
                    HasIssuerFingerprintOfOtherVersion(unhashedData),
            };
        }

        private bool HasIssuerFingerprintOfOtherVersion(SignatureSubpacket[] subpackets)
        {
            foreach (SignatureSubpacket subpacket in subpackets ?? new SignatureSubpacket[0])
            {
                if (subpacket is IssuerFingerprint issuerFingerprint && issuerFingerprint.KeyVersion != version)
                    return true;
            }
            return false;
        }

        public int Version => version;

        public int SignatureType => signatureType;

        /// <summary>Returns the key ID that created the signature.</summary>
        /// <remarks>
        /// A Key ID is an 8-octet scalar. We convert it (big-endian) to an Int64 (UInt64 is not CLS compliant).
        /// </remarks>
        public long KeyId => (long)m_keyID;

        /**
         * Return the signatures fingerprint.
         * @return fingerprint (digest prefix) of the signature
         */
        public byte[] GetFingerprint() => Arrays.Clone(fingerprint);


        /**
         * Return the signature's salt.
         * Only for v6 signatures.
         * @return salt
         */
        public byte[] GetSalt() => Arrays.Clone(m_salt);

        /**
         * return the signature trailer that must be included with the data
         * to reconstruct the signature
         *
         * @return byte[]
         */
        public byte[] GetSignatureTrailer()
        {
            if (version == 3)
            {
                long time = m_creationTime / 1000L;

                byte[] trailer = new byte[5];
                trailer[0] = (byte)signatureType;
                Pack.UInt32_To_BE((uint)time, trailer, 1);
                return trailer;
            }

            MemoryStream sOut = new MemoryStream();

            sOut.WriteByte((byte)Version);
            sOut.WriteByte((byte)SignatureType);
            sOut.WriteByte((byte)KeyAlgorithm);
            sOut.WriteByte((byte)HashAlgorithm);

            // Mark position and reserve the length field (4 octets for version 6, otherwise 2)
            bool isV6 = version == Version6;
            int lengthFieldSize = isV6 ? 4 : 2;
            long lengthPosition = sOut.Position;
            for (int i = 0; i < lengthFieldSize; ++i)
            {
                sOut.WriteByte(0x00);
            }

            // RFC 9580 5.2.4: the hashed subpackets as they were signed, not as they are encoded here
            if (m_hashedArea != null)
            {
                sOut.Write(m_hashedArea, 0, m_hashedArea.Length);
            }
            else
            {
                SignatureSubpacket[] hashed = GetHashedSubPackets();
                for (int i = 0; i != hashed.Length; i++)
                {
                    hashed[i].Encode(sOut);
                }
            }

            uint dataLength = Convert.ToUInt32(sOut.Position - lengthPosition - lengthFieldSize);
            uint hDataLength = Convert.ToUInt32(sOut.Position);

            sOut.WriteByte((byte)Version);
            sOut.WriteByte(0xFF);
            StreamUtilities.WriteUInt32BE(sOut, hDataLength);

            // Reset position and fill in length
            sOut.Position = lengthPosition;
            if (isV6)
            {
                StreamUtilities.WriteUInt32BE(sOut, dataLength);
            }
            else
            {
                StreamUtilities.WriteUInt16BE(sOut, Convert.ToUInt16(dataLength));
            }

            return sOut.ToArray();
        }

        public PublicKeyAlgorithmTag KeyAlgorithm => keyAlgorithm;

        public HashAlgorithmTag HashAlgorithm => hashAlgorithm;

        /**
         * return the signature as a set of integers - note this is normalised to be the
         * ASN.1 encoding of what appears in the signature packet.
         */
        public MPInteger[] GetSignature() => signature;

        /**
         * Return the byte encoding of the signature section.
         * @return uninterpreted signature bytes.
         */
        public byte[] GetSignatureBytes()
        {
            if (signatureEncoding != null)
                return Arrays.Clone(signatureEncoding);

            MemoryStream bOut = new MemoryStream();

            using (var pOut = new BcpgOutputStream(bOut))
            {
                foreach (MPInteger sigObj in signature)
                {
                    try
                    {
                        sigObj.Encode(pOut);
                    }
                    catch (IOException e)
                    {
                        throw new Exception("internal error: " + e);
                    }
                }
            }

            return bOut.ToArray();
        }

        // TODO[api] Ideally '..Subpackets'
        public SignatureSubpacket[] GetHashedSubPackets() => hashedData;

        // TODO[api] Ideally '..Subpackets'
        public SignatureSubpacket[] GetUnhashedSubPackets() => unhashedData;

        /// <summary>Return the creation time in milliseconds since 1 Jan., 1970 UTC.</summary>
        public long CreationTime => m_creationTime;

        public override void Encode(BcpgOutputStream bcpgOut) =>
            bcpgOut.WritePacket(HasNewPacketFormat, PacketTag.Signature, GetEncodedBody());

        /// <summary>The octets of the packet without its header.</summary>
        internal byte[] GetEncodedBody()
        {
            MemoryStream bOut = new MemoryStream();
            using (var pOut = new BcpgOutputStream(bOut))
            {
                pOut.WriteByte((byte)version);

                if (version == Version3 || version == Version2)
                {
                    byte nextBlockLength = 5;
                    pOut.Write(nextBlockLength, (byte)signatureType);
                    StreamUtilities.WriteUInt32BE(pOut, (uint)(m_creationTime / 1000L));
                    StreamUtilities.WriteUInt64BE(pOut, m_keyID);
                    pOut.Write((byte)keyAlgorithm, (byte)hashAlgorithm);
                }
                else if (version == Version4 || version == Version5 || version == Version6)
                {
                    // RFC 9580 5.2.3: version 6 signatures use 4-octet subpacket area lengths
                    bool longLengths = version == Version6;
                    pOut.Write((byte)signatureType, (byte)keyAlgorithm, (byte)hashAlgorithm);
                    EncodeLengthAndData(pOut, m_hashedArea ?? GetEncodedSubpackets(hashedData), longLengths);
                    EncodeLengthAndData(pOut, GetEncodedSubpackets(unhashedData), longLengths);
                }
                else
                {
                    throw new IOException("unknown version: " + version);
                }

                pOut.Write(fingerprint);

                if (version == Version6)
                {
                    pOut.WriteByte((byte)m_salt.Length);
                    pOut.Write(m_salt);
                }

                if (signature != null)
                {
                    pOut.WriteObjects(signature);
                }
                else
                {
                    pOut.Write(signatureEncoding);
                }
            }

            return bOut.ToArray();
        }

        private static ulong ParseKeyIdOrThrow(IssuerKeyId issuerKeyId)
        {
            try
            {
                return (ulong)issuerKeyId.GetKeyID();
            }
            catch (ArgumentException e)
            {
                throw new MalformedPacketException("Malformed IssuerKeyID subpacket.", e);
            }
        }

        private static ulong ParseKeyIdOrThrow(IssuerFingerprint issuerFingerprint)
        {
            try
            {
                return (ulong)issuerFingerprint.GetKeyID();
            }
            catch (ArgumentException e)
            {
                throw new MalformedPacketException("Malformed IssuerFingerprint subpacket.", e);
            }
        }

        private static long ParseCreationTimeOrThrow(SignatureCreationTime signatureCreationTime)
        {
            try
            {
                return DateTimeUtilities.DateTimeToUnixMs(signatureCreationTime.GetTime());
            }
            catch (Exception e)
            {
                throw new MalformedPacketException("Malformed SignatureCreationTime subpacket.", e);
            }
        }

        private SignatureSubpacket[] ReadSignatureSubpackets(BcpgInputStream bcpgIn, out byte[] encoding)
        {
            uint hashedLength;
            if (version == 6)
            {
                hashedLength = StreamUtilities.RequireUInt32BE(bcpgIn);
            }
            else
            {
                hashedLength = StreamUtilities.RequireUInt16BE(bcpgIn);
            }

            // TODO[pgp] Are we really intending to apply the individual limit to the whole list?
            if (hashedLength > SignatureSubpacketsParser.MaxSubpacketLength)
                throw new MalformedPacketException(
                    $"Signature subpackets encoding length ({hashedLength}) exceeds max limit ({SignatureSubpacketsParser.MaxSubpacketLength})");

            byte[] hashed = new byte[hashedLength];
            bcpgIn.ReadFully(hashed);
            encoding = hashed;

            SignatureSubpacketsParser sIn = new SignatureSubpacketsParser(new MemoryStream(hashed, false));

            var result = new List<SignatureSubpacket>();
            SignatureSubpacket sub;
            while ((sub = sIn.ReadPacket()) != null)
            {
                result.Add(sub);
                HasRepairedSubpackets |= sIn.IsLastRepaired;
            }
            return result.ToArray();
        }

        private static void EncodeLengthAndData(BcpgOutputStream pOut, byte[] data, bool longLength)
        {
            if (longLength)
            {
                StreamUtilities.WriteUInt32BE(pOut, (uint)data.Length);
            }
            else
            {
                // TODO[api] Refuse a subpacket area of more than 65535 octets, whose length wraps here (RFC 9580
                // 5.2.3 gives version 4 signatures two-octet lengths); the parser then leaves the signature out
                StreamUtilities.WriteUInt16BE(pOut, (ushort)data.Length);
            }
            pOut.Write(data);
        }

        /// <summary>
        /// Version 6 signatures have minimal MPIs and nothing after them (RFC 9580 3.2, 5.2.3); otherwise the packet is
        /// flagged as malformed, so that the signature never verifies, instead of rejected, so that it does not
        /// prevent the parsing of the rest of a key ring or message.
        /// </summary>
        private void CheckMpis(BcpgInputStream bcpgIn)
        {
            if (version != Version6)
                return;

            if (bcpgIn.ReadByte() >= 0)
            {
                Streams.Drain(bcpgIn);
                IsMalformed = true;
            }

            foreach (MPInteger mpi in signature)
            {
                if (!mpi.IsMinimal)
                {
                    IsMalformed = true;
                }
            }
        }

        /// <summary>
        /// Read a signature value that is a fixed-length octet string. Excess octets cannot be interpreted; they are
        /// consumed and the packet is flagged as malformed so that the signature never verifies.
        /// </summary>
        private void ReadRawSignature(BcpgInputStream bcpgIn, int length)
        {
            signature = null;
            signatureEncoding = new byte[length];
            bcpgIn.ReadFully(signatureEncoding);

            if (bcpgIn.ReadByte() >= 0)
            {
                Streams.Drain(bcpgIn);
                IsMalformed = true;
            }
        }

        private static byte[] GetEncodedSubpackets(SignatureSubpacket[] ps)
        {
            MemoryStream sOut = new MemoryStream();

            foreach (SignatureSubpacket p in ps)
            {
                p.Encode(sOut);
            }

            return sOut.ToArray();
        }

        private void SetCreationTime()
        {
            foreach (SignatureSubpacket p in hashedData)
            {
                if (p is SignatureCreationTime signatureCreationTime)
                {
                    m_creationTime = DateTimeUtilities.DateTimeToUnixMs(signatureCreationTime.GetTime());
                    break;
                }
            }
        }

        /**
         * Iterate over the hashed and unhashed signature subpackets to identify either a {@link IssuerKeyID} or
         * {@link IssuerFingerprint} subpacket to derive the issuer key-ID from.
         * The issuer {@link IssuerKeyID} and {@link IssuerFingerprint} subpacket information is "self-authenticating",
         * as its authenticity can be verified by checking the signature with the corresponding key.
         * Therefore, we can also check the unhashed signature subpacket area.
         */
        private void SetIssuerKeyId()
        {
            if (m_keyID != 0L)
                return;

            for (int idx = 0; idx != hashedData.Length; idx++)
            {
                SignatureSubpacket p = hashedData[idx];

                if (p is IssuerKeyId issuerKeyId)
                {
                    m_keyID = ParseKeyIdOrThrow(issuerKeyId);
                    return;
                }

                if (p is IssuerFingerprint issuerFingerprint)
                {
                    m_keyID = ParseKeyIdOrThrow(issuerFingerprint);
                    return;
                }
            }

            for (int idx = 0; idx != unhashedData.Length; idx++)
            {
                SignatureSubpacket p = unhashedData[idx];

                if (p is IssuerKeyId issuerKeyId)
                {
                    m_keyID = ParseKeyIdOrThrow(issuerKeyId);
                    return;
                }

                if (p is IssuerFingerprint issuerFingerprint)
                {
                    m_keyID = ParseKeyIdOrThrow(issuerFingerprint);
                    return;
                }
            }
        }

        public static SignaturePacket FromByteArray(byte[] data)
        {
            BcpgInputStream input = BcpgInputStream.Wrap(new MemoryStream(data, writable: false));

            return new SignaturePacket(input);
        }
    }
}
