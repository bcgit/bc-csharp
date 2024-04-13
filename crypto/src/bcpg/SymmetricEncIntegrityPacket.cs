using Org.BouncyCastle.Utilities;
using System;
using System.IO;

namespace Org.BouncyCastle.Bcpg
{
	public class SymmetricEncIntegrityPacket
		: InputStreamPacket
	{
        /// <summary>
        /// Version 3 SEIPD packet.
        /// </summary>
        /// <seealso href="https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-symmetrically-encrypted-int"/>
        public const int Version1 = 1;
        /// <summary>
        /// Version 2 SEIPD packet.
        /// </summary>
		/// <seealso href="https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-symmetrically-encrypted-int"/>
        public const int Version2 = 2;

        private readonly int version;                               // V1, V2
        private readonly SymmetricKeyAlgorithmTag cipherAlgorithm;  // V2 Only
        private readonly AeadAlgorithmTag aeadAlgorithm;            // V2 Only
        private readonly int chunkSize;                             // V2 Only
        private readonly byte[] salt;                               // V2 Only

        internal SymmetricEncIntegrityPacket(
			BcpgInputStream bcpgIn)
			: base(bcpgIn, PacketTag.SymmetricEncryptedIntegrityProtected)
        {
			version = bcpgIn.ReadByte();
            if (version == Version2)
            {
                cipherAlgorithm = (SymmetricKeyAlgorithmTag)bcpgIn.ReadByte();
                aeadAlgorithm = (AeadAlgorithmTag)bcpgIn.ReadByte();
                chunkSize = bcpgIn.ReadByte();

                salt = new byte[32];
                if (bcpgIn.Read(salt, 0, 32) != salt.Length)
                {
                    throw new IOException("Premature end of stream.");
                }
            }
        }

        public int Version
        {
            get { return version; }
        }

        public SymmetricKeyAlgorithmTag CipherAlgorithm
        {
            get { return cipherAlgorithm; }
        }

        public AeadAlgorithmTag AeadAlgorithm
        {
            get { return aeadAlgorithm; }
        }

        public int ChunkSize
        {
            get { return chunkSize; }
        }

        public byte[] GetSalt()
        {
            return Arrays.Clone(salt);
        }

        internal byte[] GetAAData()
        {
            return CreateAAData(Tag, Version, cipherAlgorithm, aeadAlgorithm, chunkSize);
        }

        internal static byte[] CreateAAData(PacketTag tag, int version, SymmetricKeyAlgorithmTag cipherAlgorithm, AeadAlgorithmTag aeadAlgorithm, int chunkSize)
        {
            return new byte[]{
                (byte)(0xC0 | (byte)tag),
                (byte)version,
                (byte)cipherAlgorithm,
                (byte)aeadAlgorithm,
                (byte)chunkSize
            };
        }
    }
}
