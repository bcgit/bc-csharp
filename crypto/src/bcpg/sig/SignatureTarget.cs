using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg.Sig
{
    /// <summary>
    /// Signature Subpacket containing the hash value of another signature to which this signature applies to.
    /// </summary>
    /// <remarks>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.3.25">RFC4880 - Signature Target</see>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9580.html#name-signature-target">RFC9580 - Signature Target</see>
    /// </remarks>
    public class SignatureTarget
        : SignatureSubpacket
    {
        public SignatureTarget(bool critical, bool isLongLength, byte[] data)
            : base(SignatureSubpacketTag.SignatureTarget, critical, isLongLength, VerifyData(data))
        {
        }

        public SignatureTarget(bool critical, int publicKeyAlgorithm, int hashAlgorithm, byte[] hashData)
            : base(SignatureSubpacketTag.SignatureTarget, critical, isLongLength: false,
                  Arrays.Concatenate(new byte[]{ (byte)publicKeyAlgorithm, (byte)hashAlgorithm }, hashData))
        {
        }

        // RFC 9580 5.2.3.33: the Signature Target body is 1 octet public-key algorithm, 1 octet
        // hash algorithm, then N octets of hash; the two leading octets must be present.
        private static byte[] VerifyData(byte[] data)
        {
            if (data.Length < 2)
                throw new ArgumentException("Truncated signature target subpacket", nameof(data));

            return data;
        }

        public int PublicKeyAlgorithm => Data[0];

        public int HashAlgorithm => Data[1];

        public byte[] GetHashData() => Arrays.CopyOfRange(Data, 2, Data.Length);
    }
}
