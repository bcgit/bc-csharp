using System;
using System.Text;

using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Bcpg
{
    public static class FingerprintUtilities
    {
        /// <summary>Derive a key-id from the given key fingerprint.</summary>
        /// <remarks>
        /// This method can derive key-ids from v4, v5 (LibrePGP) and v6 keys. For keys with other versions (2,3) it
        /// will return 0.
        /// </remarks>
        public static long KeyIDFromFingerprint(int keyVersion, byte[] fingerprint)
        {
            if (keyVersion == PublicKeyPacket.Version4)
                return KeyIDFromV4Fingerprint(fingerprint);

            if (keyVersion == PublicKeyPacket.LibrePgp5)
                return KeyIDFromLibrePgpFingerprint(fingerprint);

            if (keyVersion == PublicKeyPacket.Version6)
                return KeyIDFromV6Fingerprint(fingerprint);

            return 0L;
        }

        /// <summary>Derive a 64 bit key-id from a version 6 OpenPGP fingerprint.</summary>
        /// <remarks>For v6 keys, the key-id corresponds to the left-most 8 octets of the fingerprint.</remarks>
        public static long KeyIDFromV6Fingerprint(byte[] v6Fingerprint) => LongFromLeftMostBytes(v6Fingerprint);

        /// <summary>Derive a 64 bit key-id from a version 5 LibrePGP fingerprint.</summary>
        /// <remarks>For such keys, the key-id corresponds to the left-most 8 octets of the fingerprint.</remarks>
        public static long KeyIDFromLibrePgpFingerprint(byte[] v5Fingerprint) => LongFromLeftMostBytes(v5Fingerprint);

        /// <summary>Derive a 64 bit key-id from a version 4 OpenPGP fingerprint.</summary>
        /// <remarks>For v4 keys, the key-id corresponds to the right-most 8 octets of the fingerprint.</remarks>
        public static long KeyIDFromV4Fingerprint(byte[] v4Fingerprint) => LongFromRightMostBytes(v4Fingerprint);

        /// <summary>Convert the left-most 8 bytes from the given array to a long.</summary>
        public static long LongFromLeftMostBytes(byte[] bytes) => ReadKeyID(bytes, 0);

        /// <summary>Convert the right-most 8 bytes from the given array to a long.</summary>
        public static long LongFromRightMostBytes(byte[] bytes) => ReadKeyID(bytes, bytes.Length - 8);

        /// <summary>Read a key-ID from 8 octets of the given byte array starting at offset.</summary>
        public static long ReadKeyID(byte[] bytes, int offset)
        {
            Arrays.ValidateSegment(bytes, offset, 8);

            return (long)Pack.BE_To_UInt64(bytes, offset);
        }

        /// <summary>Write the key-ID encoded as 8 octets to the given byte array, starting at index offset.</summary>
        public static void WriteKeyID(long keyID, byte[] bytes, int offset)
        {
            Arrays.ValidateSegment(bytes, offset, 8);

            Pack.UInt64_To_BE((ulong)keyID, bytes, offset);
        }
    }
}
