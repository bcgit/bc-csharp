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
        /// <summary>Create a new <see cref="SignatureTarget"/>.</summary>
        /// <param name="critical">Whether the extension is critical.</param>
        /// <param name="isLongLength">true if the long length form is used, false otherwise.</param>
        /// <param name="data">The data.</param>
        public SignatureTarget(bool critical, bool isLongLength, byte[] data)
            : base(SignatureSubpacketTag.SignatureTarget, critical, isLongLength, VerifyData(data))
        {
        }

        /// <summary>Create a new <see cref="SignatureTarget"/>.</summary>
        /// <param name="critical">Whether the extension is critical.</param>
        /// <param name="publicKeyAlgorithm">The public key algorithm.</param>
        /// <param name="hashAlgorithm">The hash algorithm.</param>
        /// <param name="hashData">The hash data.</param>
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

        /// <summary>Gets the public key algorithm.</summary>
        public int PublicKeyAlgorithm => Data[0];

        /// <summary>Gets the hash algorithm.</summary>
        public int HashAlgorithm => Data[1];

        /// <summary>Return the hash data.</summary>
        public byte[] GetHashData() => Arrays.CopyOfRange(Data, 2, Data.Length);
    }
}
