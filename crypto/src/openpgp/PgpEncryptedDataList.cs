using System;
using System.Collections.Generic;
using System.IO;

using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <remarks>A holder for a list of PGP encryption method packets.</remarks>
    public class PgpEncryptedDataList
		: PgpObject
    {
        private readonly List<PgpEncryptedData> m_list = new List<PgpEncryptedData>();
        private readonly InputStreamPacket m_data;

        public PgpEncryptedDataList(BcpgInputStream bcpgInput)
        {
            var packets = new List<Packet>();
            while (bcpgInput.NextPacketTag() == PacketTag.PublicKeyEncryptedSession
                || bcpgInput.NextPacketTag() == PacketTag.SymmetricKeyEncryptedSessionKey)
            {
                packets.Add(bcpgInput.ReadPacket());
            }

            Packet lastPacket = bcpgInput.ReadPacket();
            if (!(lastPacket is InputStreamPacket inputStreamPacket))
                throw new IOException("unexpected packet in stream: " + lastPacket);

            m_data = inputStreamPacket;

            foreach (var packet in packets)
            {
                if (packet is SymmetricKeyEncSessionPacket symmetricKey)
                {
                    m_list.Add(new PgpPbeEncryptedData(symmetricKey, m_data));
                }
                else if (packet is PublicKeyEncSessionPacket publicKey)
                {
                    m_list.Add(new PgpPublicKeyEncryptedData(publicKey, m_data));
                }
                else
                {
                    throw new InvalidOperationException();
                }
            }
        }

		public PgpEncryptedData this[int index] => m_list[index];

		public int Count => m_list.Count;

        public bool IsEmpty => m_list.Count == 0;

		public IEnumerable<PgpEncryptedData> GetEncryptedDataObjects()
        {
            return CollectionUtilities.Proxy(m_list);
        }
    }
}
