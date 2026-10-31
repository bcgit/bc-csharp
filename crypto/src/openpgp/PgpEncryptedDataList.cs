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
            while (bcpgInput.SkipIgnoredPackets() == PacketTag.PublicKeyEncryptedSession
                || bcpgInput.NextPacketTag() == PacketTag.SymmetricKeyEncryptedSessionKey)
            {
                try
                {
                    packets.Add(bcpgInput.ReadPacket());
                }
                catch (UnsupportedPacketVersionException)
                {
                    // Session key packets of unsupported versions are ignored, like signatures
                }
            }

            bcpgInput.SkipIgnoredPackets();

            Packet lastPacket = bcpgInput.ReadPacket();
            if (!(lastPacket is InputStreamPacket inputStreamPacket))
                throw new IOException("unexpected packet in stream: " + lastPacket);

            m_data = inputStreamPacket;

            foreach (var packet in packets)
            {
                // RFC 9580 10.3.2.1: ESK packets with a version that does not align with the payload are discarded
                if (!IsAligned(packet, m_data))
                    continue;

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

        /// <summary>
        /// Whether the version of an ESK packet fits the payload: v3 PKESK and v4 SKESK go with SED and v1 SEIPD
        /// packets, v6 PKESK and v6 SKESK with v2 SEIPD packets.
        /// </summary>
        private static bool IsAligned(Packet esk, InputStreamPacket payload)
        {
            bool isPkesk = esk is PublicKeyEncSessionPacket;
            int eskVersion = isPkesk
                ? ((PublicKeyEncSessionPacket)esk).Version
                : ((SymmetricKeyEncSessionPacket)esk).Version;

            if (payload is SymmetricEncIntegrityPacket seipd)
            {
                switch (seipd.Version)
                {
                case SymmetricEncIntegrityPacket.Version1:
                    return eskVersion == (isPkesk ? PublicKeyEncSessionPacket.Version3
                        : SymmetricKeyEncSessionPacket.Version4);
                case SymmetricEncIntegrityPacket.Version2:
                    return eskVersion == (isPkesk ? PublicKeyEncSessionPacket.Version6
                        : SymmetricKeyEncSessionPacket.Version6);
                default:
                    // A payload of an unknown version is reported as such when decrypting
                    return true;
                }
            }

            if (payload is SymmetricEncDataPacket)
            {
                return eskVersion == (isPkesk ? PublicKeyEncSessionPacket.Version3
                    : SymmetricKeyEncSessionPacket.Version4);
            }

            if (payload is AeadEncDataPacket)
            {
                // LibrePGP OCB encrypted data
                return eskVersion == (isPkesk ? PublicKeyEncSessionPacket.Version3
                    : SymmetricKeyEncSessionPacket.Version5);
            }

            return true;
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
