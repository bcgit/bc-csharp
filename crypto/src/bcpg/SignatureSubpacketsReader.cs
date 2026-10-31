using System;
using System.IO;

using Org.BouncyCastle.Bcpg.Sig;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Bcpg
{
    /// <summary>Parser for signature subpackets</summary>
    public class SignatureSubpacketsParser
    {
        /// <summary>2MiB, allows for embedded McEliece keys for example.</summary>
        public static readonly int MaxSubpacketLength = 2 * 1024 * 1024;

        private readonly Stream m_input;
        private readonly int m_limit;

        public SignatureSubpacketsParser(Stream input)
            : this(input, StreamUtilities.FindLimit(input))
        {
        }

        public SignatureSubpacketsParser(Stream input, int limit)
        {
            m_input = input;
            m_limit = limit;
        }

        /// <summary>
        /// Whether the last subpacket read was shorter than its length said, and taken at its fixed length (a
        /// repair for implementations that write wrong lengths, which RFC 9580 5.2.5 calls malformed).
        /// </summary>
        internal bool IsLastRepaired { get; private set; }

        // TODO[api] Make virtual?
        public SignatureSubpacket ReadPacket()
        {
            // RFC 9580 5.2.3.7: unlike packet lengths, subpacket lengths have no partial lengths, and a first octet
            // from 192 to 254 starts a two-octet length
            int b0 = m_input.ReadByte();
            if (b0 < 0)
                return null;

            uint bodyLen;
            bool isLongLength = b0 == 255;
            if (b0 < 192)
            {
                bodyLen = (uint)b0;
            }
            else if (!isLongLength)
            {
                bodyLen = (uint)(((b0 - 192) << 8) + StreamUtilities.RequireByte(m_input) + 192);
            }
            else
            {
                bodyLen = StreamUtilities.RequireUInt32BE(m_input);
            }

            if (bodyLen < 1U)
                throw new MalformedPacketException("Body length octet too small.");
            // see below about miscoding... we'll try not to panic about anything under 2K.
            if (bodyLen > m_limit && bodyLen > 2048)
                throw new MalformedPacketException($"Body length octet ({bodyLen}) exceeds limit ({m_limit}).");
            // Absolute cap, independent of the FindLimit() hint, so a crafted length cannot drive a huge allocation.
            if (bodyLen > MaxSubpacketLength)
                throw new MalformedPacketException(
                    $"Body length octet ({bodyLen}) exceeds max signature subpacket length ({MaxSubpacketLength}).");

            //// see below about miscoding... we'll try not to panic about anything under 2K.
            //if (bodyLen < 1U || (bodyLen > m_limit && bodyLen > 2048))
            //    throw new EndOfStreamException("out of range data found in signature subpacket");

            int tag = StreamUtilities.RequireByte(m_input);
            byte[] data = new byte[bodyLen - 1];

            //
            // this may seem a bit strange but it turns out some applications miscode the length
            // in fixed length fields, so we check the length we do get, only throwing an exception if
            // we really cannot continue
            //
            int bytesRead = Streams.ReadFully(m_input, data);

            bool isCritical = (tag & 0x80) != 0;
            SignatureSubpacketTag type = (SignatureSubpacketTag)(tag & 0x7F);

            IsLastRepaired = bytesRead != data.Length;
            if (IsLastRepaired)
            {
                switch (type)
                {
                case SignatureSubpacketTag.CreationTime:
                    data = CheckData(data, 4, bytesRead, "Signature Creation Time");
                    break;
                case SignatureSubpacketTag.IssuerKeyId:
                    data = CheckData(data, 8, bytesRead, "Issuer");
                    break;
                case SignatureSubpacketTag.KeyExpireTime:
                    data = CheckData(data, 4, bytesRead, "Signature Key Expiration Time");
                    break;
                case SignatureSubpacketTag.ExpireTime:
                    data = CheckData(data, 4, bytesRead, "Signature Expiration Time");
                    break;
                default:
                    throw new EndOfStreamException("truncated subpacket data.");
                }
            }

            try
            {
                switch (type)
                {
                case SignatureSubpacketTag.CreationTime:
                    return new SignatureCreationTime(isCritical, isLongLength, data);
                case SignatureSubpacketTag.EmbeddedSignature:
                    return new EmbeddedSignature(isCritical, isLongLength, data);
                case SignatureSubpacketTag.KeyExpireTime:
                    return new KeyExpirationTime(isCritical, isLongLength, data);
                case SignatureSubpacketTag.ExpireTime:
                    return new SignatureExpirationTime(isCritical, isLongLength, data);
                case SignatureSubpacketTag.Revocable:
                    return new Revocable(isCritical, isLongLength, data);
                case SignatureSubpacketTag.Exportable:
                    return new Exportable(isCritical, isLongLength, data);
                case SignatureSubpacketTag.Features:
                    return new Features(isCritical, isLongLength, data);
                case SignatureSubpacketTag.IssuerKeyId:
                    return new IssuerKeyId(isCritical, isLongLength, data);
                case SignatureSubpacketTag.TrustSig:
                    return new TrustSignature(isCritical, isLongLength, data);
                case SignatureSubpacketTag.PreferredCompressionAlgorithms:
                case SignatureSubpacketTag.PreferredHashAlgorithms:
                case SignatureSubpacketTag.PreferredSymmetricAlgorithms:
                    return new PreferredAlgorithms(type, isCritical, isLongLength, data);
                case SignatureSubpacketTag.PreferredAeadAlgorithms:
                    try
                    {
                        return new PreferredAeadCiphersuites(isCritical, isLongLength, data);
                    }
                    catch (ArgumentException)
                    {
                        // Not a list of pairs; keep the subpacket so that the signature can still be parsed
                        return new PreferredAlgorithms(type, isCritical, isLongLength, data);
                    }
                case SignatureSubpacketTag.KeyFlags:
                    return new KeyFlags(isCritical, isLongLength, data);
                case SignatureSubpacketTag.PolicyUrl:
                    return new PolicyUrl(isCritical, isLongLength, data);
                case SignatureSubpacketTag.PrimaryUserId:
                    return new PrimaryUserId(isCritical, isLongLength, data);
                case SignatureSubpacketTag.SignerUserId:
                    return new SignerUserId(isCritical, isLongLength, data);
                case SignatureSubpacketTag.NotationData:
                    return new NotationData(isCritical, isLongLength, data);
                case SignatureSubpacketTag.RegExp:
                    return new RegularExpression(isCritical, isLongLength, data);
                case SignatureSubpacketTag.RevocationReason:
                    return new RevocationReason(isCritical, isLongLength, data);
                case SignatureSubpacketTag.RevocationKey:
                    return new RevocationKey(isCritical, isLongLength, data);
                case SignatureSubpacketTag.SignatureTarget:
                    return new SignatureTarget(isCritical, isLongLength, data);
                case SignatureSubpacketTag.IssuerFingerprint:
                    return new IssuerFingerprint(isCritical, isLongLength, data);
                case SignatureSubpacketTag.IntendedRecipientFingerprint:
                    return new IntendedRecipientFingerprint(isCritical, isLongLength, data);
                }
            }
            catch (ArgumentException e)
            {
                throw new MalformedPacketException("Malformed signature subpacket.", e);
            }

            return new SignatureSubpacket(type, isCritical, isLongLength, data);
        }

        private static byte[] CheckData(byte[] data, int expected, int bytesRead, string name)
        {
            if (bytesRead != expected)
                throw new EndOfStreamException("truncated " + name + " subpacket data.");

            return Arrays.CopyOfRange(data, 0, expected);
        }
    }
}
