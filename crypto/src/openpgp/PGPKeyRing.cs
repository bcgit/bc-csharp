using System;
using System.Collections.Generic;
using System.IO;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
	public abstract class PgpKeyRing
		: PgpObject
	{
		internal PgpKeyRing()
		{
		}

        internal static TrustPacket ReadOptionalTrustPacket(BcpgInputStream pIn)
		{
            PacketTag tag = pIn.SkipIgnoredPackets();

            return tag == PacketTag.Trust ? (TrustPacket)pIn.ReadPacket() : null;
		}

		internal static IList<PgpSignature> ReadSignaturesAndTrust(BcpgInputStream pIn)
		{
            try
            {
				var sigList = new List<PgpSignature>();

				while (pIn.SkipIgnoredPackets() == PacketTag.Signature)
				{
					SignaturePacket signaturePacket;
					try
					{
						signaturePacket = (SignaturePacket)pIn.ReadPacket();
					}
					catch (Exception e) when (e is UnsupportedPacketVersionException ||
						e is MalformedSignaturePacketException)
					{
						// Signatures of unsupported versions, and malformed ones, are ignored (RFC 9580 5.2.5); the
						// packet has already been consumed
						ReadOptionalTrustPacket(pIn);
						continue;
					}

					TrustPacket trustPacket = ReadOptionalTrustPacket(pIn);

					sigList.Add(new PgpSignature(signaturePacket, trustPacket));
				}

				return sigList;
			}
			catch (PgpException e)
			{
				throw new IOException("can't create signature object: " + e.Message, e);
			}
		}

		internal static void ReadUserIDs(BcpgInputStream pIn, out IList<IUserDataPacket> ids,
			out IList<TrustPacket> idTrusts, out IList<IList<PgpSignature>> idSigs)
		{
			ids = new List<IUserDataPacket>();
			idTrusts = new List<TrustPacket>();
			idSigs = new List<IList<PgpSignature>>();

            while (IsUserTag(pIn.SkipIgnoredPackets()))
			{
				Packet obj = pIn.ReadPacket();
				if (obj is UserIdPacket id)
				{
					ids.Add(id);
				}
				else
				{
					UserAttributePacket user = (UserAttributePacket)obj;
					ids.Add(new PgpUserAttributeSubpacketVector(user.GetSubpackets()));
				}

				idTrusts.Add(ReadOptionalTrustPacket(pIn));
				idSigs.Add(ReadSignaturesAndTrust(pIn));
			}
		}

        private static bool IsUserTag(PacketTag tag)
        {
            switch (tag)
            {
                case PacketTag.UserAttribute:
                case PacketTag.UserId:
                    return true;
                default:
                    return false;
            }
        }
	}
}
