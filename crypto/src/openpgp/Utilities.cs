using System.Collections.Generic;
using System.IO;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    internal class Utilities
    {
        internal static BcpgInputStream CreateBcpgInputStream(Stream pgIn, PacketTag tag)
        {
            BcpgInputStream bcIn = BcpgInputStream.Wrap(pgIn);
            PacketTag nextTag = bcIn.NextPacketTag();

            if (nextTag == tag)
                return bcIn;

            throw new IOException("unexpected tag " + nextTag + " encountered");
        }

        internal static BcpgInputStream CreateBcpgInputStream(Stream pgIn, PacketTag tag1, PacketTag tag2)
        {
            BcpgInputStream bcIn = BcpgInputStream.Wrap(pgIn);
            PacketTag nextTag = bcIn.NextPacketTag();

            if (nextTag == tag1 || nextTag == tag2)
                return bcIn;

            throw new IOException("unexpected tag " + nextTag + " encountered");
        }

        internal static void EncodePgpSignatures(Stream stream, IEnumerable<PgpSignature> sigs, bool forTransfer)
        {
            foreach (var sig in sigs)
            {
                sig.Encode(stream, forTransfer);
            }
        }
    }
}
