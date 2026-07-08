using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg
{
    /// <summary>
    /// Represents revocation key OpenPGP signature sub packet. Note: This packet is deprecated. Applications MUST NOT
    /// generate such a packet.
    /// </summary>
    /// <remarks>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.3.15">RFC4880 - Revocation Key</see>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9580.html#name-revocation-key">RFC9580 - Revocation Key</see>
    /// <para>Deprecated since RFC9580.</para>
    /// </remarks>
    public class RevocationKey
        : SignatureSubpacket
    {
        // 1 octet of class, 
        // 1 octet of public-key algorithm ID, 
        // 20 octets of fingerprint
        public RevocationKey(bool isCritical, bool isLongLength, byte[] data)
            : base(SignatureSubpacketTag.RevocationKey, isCritical, isLongLength, VerifyData(data))
        {
        }

        public RevocationKey(bool isCritical, RevocationKeyTag signatureClass, PublicKeyAlgorithmTag keyAlgorithm,
            byte[] fingerprint)
            : base(SignatureSubpacketTag.RevocationKey, isCritical, isLongLength: false,
                CreateData(signatureClass, keyAlgorithm, fingerprint))
        {
        }

        private static byte[] CreateData(RevocationKeyTag signatureClass, PublicKeyAlgorithmTag keyAlgorithm,
            byte[] fingerprint)
        {
            byte[] data = new byte[2 + fingerprint.Length];
            data[0] = (byte)signatureClass;
            data[1] = (byte)keyAlgorithm;
            Array.Copy(fingerprint, 0, data, 2, fingerprint.Length);
            return data;
        }

        // RFC 9580 5.2.3.23: the Revocation Key body is 1 octet of class, 1 octet of public-key
        // algorithm, then the fingerprint; the two fixed leading octets must be present (the
        // fingerprint length is key-version dependent and is not constrained here).
        private static byte[] VerifyData(byte[] data)
        {
            if (data.Length < 2)
                throw new ArgumentException("Truncated revocation key subpacket", nameof(data));

            return data;
        }

        public virtual RevocationKeyTag SignatureClass => (RevocationKeyTag)Data[0];

        public virtual PublicKeyAlgorithmTag Algorithm => (PublicKeyAlgorithmTag)Data[1];

        public virtual byte[] GetFingerprint() => Arrays.CopyOfRange(Data, 2, Data.Length);
    }
}
