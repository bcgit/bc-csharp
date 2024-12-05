using System.IO;

using Org.BouncyCastle.Bcpg.Sig;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Bcpg
{
    /**
	* reader for signature sub-packets
	*/
    public class SignatureSubpacketsParser
	{
		private readonly Stream m_input;

		public SignatureSubpacketsParser(Stream input)
		{
			m_input = input;
		}

		public SignatureSubpacket ReadPacket()
		{
            int bodyLen = StreamUtilities.ReadBodyLen(m_input, out var streamFlags);
            if (bodyLen < 0)
                return null;

            if (streamFlags.HasFlag(StreamUtilities.StreamFlags.Partial))
                throw new IOException("unexpected length header");

            bool isLongLength = streamFlags.HasFlag(StreamUtilities.StreamFlags.LongLength);

            if (bodyLen < 1)
                throw new EndOfStreamException("out of range data found in signature sub packet");

            int tag = StreamUtilities.RequireByte(m_input);

            byte[] data = new byte[bodyLen - 1];

            //
            // this may seem a bit strange but it turns out some applications miscode the length
            // in fixed length fields, so we check the length we do get, only throwing an exception if
            // we really cannot continue
            //
            int bytesRead = Streams.ReadFully(m_input, data);

            bool isCritical = ((tag & 0x80) != 0);
            SignatureSubpacketTag type = (SignatureSubpacketTag)(tag & 0x7f);

            if (bytesRead != data.Length)
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
			case SignatureSubpacketTag.PreferredAeadAlgorithms:
                return new PreferredAlgorithms(type, isCritical, isLongLength, data);
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
            return new SignatureSubpacket(type, isCritical, isLongLength, data);
		}

        private byte[] CheckData(byte[] data, int expected, int bytesRead, string name)
        {
            if (bytesRead != expected)
                throw new EndOfStreamException("truncated " + name + " subpacket data.");

            return Arrays.CopyOfRange(data, 0, expected);
        }
	}
}
