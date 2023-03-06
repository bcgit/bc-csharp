using System;
using System.Collections.Generic;
using System.IO;

using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <remarks>
    /// Class to hold a single master public key and its subkeys.
    /// <p>
    /// Often PGP keyring files consist of multiple master keys, if you are trying to process
    /// or construct one of these you should use the <c>PgpPublicKeyRingBundle</c> class.
    /// </p>
    /// </remarks>
    public class PgpPublicKeyRing
        : PgpKeyRing
    {
        private readonly IList<PgpPublicKey> keys;

        public PgpPublicKeyRing(
            byte[] encoding)
            : this(new MemoryStream(encoding, false))
        {
        }

        internal PgpPublicKeyRing(IList<PgpPublicKey> pubKeys)
        {
            this.keys = pubKeys;
        }

        public PgpPublicKeyRing(
            Stream inputStream)
        {
            this.keys = new List<PgpPublicKey>();

            BcpgInputStream bcpgInput = BcpgInputStream.Wrap(inputStream);

            PacketTag initialTag = bcpgInput.SkipMarkerPackets();
            if (initialTag != PacketTag.PublicKey && initialTag != PacketTag.PublicSubkey)
            {
                throw new IOException("public key ring doesn't start with public key tag: "
                    + "tag 0x" + ((int)initialTag).ToString("X"));
            }

            PublicKeyPacket pubPk = ReadPublicKeyPacket(bcpgInput);
            TrustPacket trustPk = ReadOptionalTrustPacket(bcpgInput);

            // direct signatures and revocations
            var keySigs = ReadSignaturesAndTrust(bcpgInput);

            ReadUserIDs(bcpgInput, out var ids, out var idTrusts, out var idSigs);

            keys.Add(new PgpPublicKey(pubPk, trustPk, keySigs, ids, idTrusts, idSigs));


            // Read subkeys
            while (bcpgInput.NextPacketTag() == PacketTag.PublicSubkey)
            {
                keys.Add(ReadSubkey(bcpgInput));
            }
        }

        /// <summary>Return the first public key in the ring.</summary>
        public virtual PgpPublicKey GetPublicKey()
        {
            return keys[0];
        }

        /// <summary>Return the public key referred to by the passed in key ID if it is present.</summary>
        public virtual PgpPublicKey GetPublicKey(long keyId)
        {
            foreach (PgpPublicKey k in keys)
            {
                if (keyId == k.KeyId)
                    return k;
            }

            return null;
        }

        /// <summary>Allows enumeration of all the public keys.</summary>
        /// <returns>An <c>IEnumerable</c> of <c>PgpPublicKey</c> objects.</returns>
        public virtual IEnumerable<PgpPublicKey> GetPublicKeys()
        {
            return CollectionUtilities.Proxy(keys);
        }

        public virtual byte[] GetEncoded()
        {
            MemoryStream bOut = new MemoryStream();

            Encode(bOut);

            return bOut.ToArray();
        }

        public virtual void Encode(
            Stream outStr)
        {
            if (outStr == null)
                throw new ArgumentNullException("outStr");

            foreach (PgpPublicKey k in keys)
            {
                k.Encode(outStr);
            }
        }

        /// <summary>
        /// Returns a new key ring with the public key passed in either added or
        /// replacing an existing one.
        /// </summary>
        /// <param name="pubRing">The public key ring to be modified.</param>
        /// <param name="pubKey">The public key to be inserted.</param>
        /// <returns>A new <c>PgpPublicKeyRing</c></returns>
        public static PgpPublicKeyRing InsertPublicKey(
            PgpPublicKeyRing	pubRing,
            PgpPublicKey		pubKey)
        {
            var keys = new List<PgpPublicKey>(pubRing.keys);
            bool found = false;
            bool masterFound = false;

            for (int i = 0; i != keys.Count; i++)
            {
                PgpPublicKey key = keys[i];

                if (key.KeyId == pubKey.KeyId)
                {
                    found = true;
                    keys[i] = pubKey;
                }
                if (key.IsMasterKey)
                {
                    masterFound = true;
                }
            }

            if (!found)
            {
                if (pubKey.IsMasterKey)
                {
                    if (masterFound)
                        throw new ArgumentException("cannot add a master key to a ring that already has one");

                    keys.Insert(0, pubKey);
                }
                else
                {
                    keys.Add(pubKey);
                }
            }

            return new PgpPublicKeyRing(keys);
        }

        /// <summary>Returns a new key ring with the public key passed in removed from the key ring.</summary>
        /// <param name="pubRing">The public key ring to be modified.</param>
        /// <param name="pubKey">The public key to be removed.</param>
        /// <returns>A new <c>PgpPublicKeyRing</c>, or null if pubKey is not found.</returns>
        public static PgpPublicKeyRing RemovePublicKey(PgpPublicKeyRing pubRing, PgpPublicKey pubKey)
        {
            int count = pubRing.keys.Count;
            long keyID = pubKey.KeyId;

            var result = new List<PgpPublicKey>(count);
            bool found = false;

            foreach (var key in pubRing.keys)
            {
                if (key.KeyId == keyID)
                {
                    found = true;
                    continue;
                }

                result.Add(key);
            }

            return found ? new PgpPublicKeyRing(result) : null;
        }

        internal static PublicKeyPacket ReadPublicKeyPacket(BcpgInputStream bcpgInput)
        {
            Packet packet = bcpgInput.ReadPacket();
            if (!(packet is PublicKeyPacket publicKeyPacket))
                throw new IOException("unexpected packet in stream: " + packet);

            return publicKeyPacket;
        }

        internal static PgpPublicKey ReadSubkey(BcpgInputStream bcpgInput)
        {
            PublicKeyPacket	pk = ReadPublicKeyPacket(bcpgInput);
            TrustPacket kTrust = ReadOptionalTrustPacket(bcpgInput);

            // PGP 8 actually leaves out the signature.
            var sigList = ReadSignaturesAndTrust(bcpgInput);

            return new PgpPublicKey(pk, kTrust, sigList);
        }

        /**
         * Join two copies of the same certificate.
         * The certificates must have the same primary key, but may carry different subkeys, user-ids and signatures.
         * The resulting certificate will carry the sum of both certificates subkeys, user-ids and signatures.
         * <p>
         * This method will ignore trust packets on the second copy of the certificate and instead
         * copy the local certificate's trust packets to the joined certificate.
         *
         * @param first  local copy of the certificate
         * @param second remote copy of the certificate (e.g. from a key server)
         * @return joined key ring
         * @throws PGPException
         */
        public static PgpPublicKeyRing Join(PgpPublicKeyRing first, PgpPublicKeyRing second)
        {
            return Join(first, second, false, false);
        }

        /**
         * Join two copies of the same certificate.
         * The certificates must have the same primary key, but may carry different subkeys, user-ids and signatures.
         * The resulting certificate will carry the sum of both certificates subkeys, user-ids and signatures.
         * <p>
         * For each subkey holds: If joinTrustPackets is set to true and the second key is carrying a trust packet,
         * the trust packet will be copied to the joined key.
         * Otherwise, the joined key will carry the trust packet of the local copy.
         *
         * @param first                      local copy of the certificate
         * @param second                     remote copy of the certificate (e.g. from a key server)
         * @param joinTrustPackets           if true, trust packets from the second certificate copy will be carried over into the joined certificate
         * @param allowSubkeySigsOnNonSubkey if true, the resulting joined certificate may carry subkey signatures on its primary key
         * @return joined certificate
         * @throws PGPException
         */
        public static PgpPublicKeyRing Join(PgpPublicKeyRing first, PgpPublicKeyRing second, bool joinTrustPackets,
            bool allowSubkeySigsOnNonSubkey)
        {
            if (!Arrays.AreEqual(first.GetPublicKey().GetFingerprint(), second.GetPublicKey().GetFingerprint()))
                throw new ArgumentException("Cannot merge certificates with differing primary keys.");

            var secondKeys = new HashSet<long>();
            foreach (var key in second.GetPublicKeys())
            {
                secondKeys.Add(key.KeyId);
            }

            var merged = new List<PgpPublicKey>();
            foreach (var key in first.GetPublicKeys())
            {
                var copy = second.GetPublicKey(key.KeyId);
                if (copy != null)
                {
                    merged.Add(PgpPublicKey.Join(key, copy, joinTrustPackets, allowSubkeySigsOnNonSubkey));
                    secondKeys.Remove(key.KeyId);
                }
                else
                {
                    merged.Add(key);
                }
            }

            foreach (var additionalKeyId in secondKeys)
            {
                merged.Add(second.GetPublicKey(additionalKeyId));
            }

            return new PgpPublicKeyRing(merged);
        }
    }
}
