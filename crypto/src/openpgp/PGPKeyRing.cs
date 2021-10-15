using System.Collections;
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
            PacketTag tag = pIn.SkipMarkerPackets();

            return tag == PacketTag.Trust ? (TrustPacket)pIn.ReadPacket() : null;
		}

		internal static IList ReadSignaturesAndTrust(BcpgInputStream pIn)
		{
            try
            {
				IList sigList = Platform.CreateArrayList();

				while (pIn.SkipMarkerPackets() == PacketTag.Signature)
				{
					SignaturePacket signaturePacket = (SignaturePacket)pIn.ReadPacket();
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

		internal static void ReadUserIDs(BcpgInputStream pIn, out IList ids, out IList idTrusts, out IList idSigs)
		{
			ids = Platform.CreateArrayList();
            idTrusts = Platform.CreateArrayList();
            idSigs = Platform.CreateArrayList();

            while (IsUserTag(pIn.SkipMarkerPackets()))
			{
				Packet obj = pIn.ReadPacket();
				if (obj is UserIdPacket)
				{
					UserIdPacket id = (UserIdPacket)obj;
					ids.Add(id.GetId());
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
