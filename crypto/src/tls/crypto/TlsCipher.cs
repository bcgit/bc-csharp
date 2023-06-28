﻿using System;
using System.IO;

namespace Org.BouncyCastle.Tls.Crypto
{
    /// <summary>Base interface for a TLS bulk cipher.</summary>
    public interface TlsCipher
    {
        /// <summary>Return the maximum input size for a ciphertext given a maximum output size for the plaintext of
        /// plaintextLimit bytes.</summary>
        /// <param name="plaintextLimit">the maximum output size for the plaintext.</param>
        /// <returns>the maximum input size of the ciphertext for plaintextlimit bytes of output.</returns>
        int GetCiphertextDecodeLimit(int plaintextLimit);

        /// <summary>Return the maximum output size for a ciphertext given an actual input plaintext size of
        /// plaintextLength bytes and a maximum input plaintext size of plaintextLimit bytes.</summary>
        /// <param name="plaintextLength">the actual input size for the plaintext.</param>
        /// <param name="plaintextLimit">the maximum input size for the plaintext.</param>
        /// <returns>the maximum output size of the ciphertext for plaintextlimit bytes of input.</returns>
        // TODO[api] Only need plaintextLimit parameter (receiving current callers' plaintextLength)
        int GetCiphertextEncodeLimit(int plaintextLength, int plaintextLimit);

        /// <summary>Return the maximum size for the plaintext given ciphertextlimit bytes of ciphertext.</summary>
        /// <param name="ciphertextLimit">the maximum number of bytes of ciphertext.</param>
        /// <returns>the maximum size of the plaintext for ciphertextlimit bytes of input.</returns>
        // TODO[api] Remove
        int GetPlaintextLimit(int ciphertextLimit);

        /// <summary>Encode the passed in plaintext using the current bulk cipher.</summary>
        /// <param name="seqNo">sequence number of the message represented by plaintext.</param>
        /// <param name="contentType">content type of the message represented by plaintext.</param>
        /// <param name="recordVersion"><see cref="ProtocolVersion"/> used for the record.</param>
        /// <param name="headerAllocation">extra bytes to allocate at start of returned byte array.</param>
        /// <param name="plaintext">array holding input plaintext to the cipher.</param>
        /// <param name="offset">offset into input array the plaintext starts at.</param>
        /// <param name="len">length of the plaintext in the array.</param>
        /// <returns>A <see cref="TlsEncodeResult"/> containing the result of encoding (after 'headerAllocation' unused
        /// bytes).</returns>
        /// <exception cref="IOException"/>
        // TODO[api] Add a parameter for how much (D)TLSInnerPlaintext padding to add
        TlsEncodeResult EncodePlaintext(long seqNo, short contentType, ProtocolVersion recordVersion,
            int headerAllocation, byte[] plaintext, int offset, int len);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        // TODO[api] Add a parameter for how much (D)TLSInnerPlaintext padding to add
        TlsEncodeResult EncodePlaintext(long seqNo, short contentType, ProtocolVersion recordVersion,
            int headerAllocation, ReadOnlySpan<byte> plaintext);
#endif

        /// <summary>Decode the passed in ciphertext using the current bulk cipher.</summary>
        /// <param name="seqNo">sequence number of the message represented by ciphertext.</param>
        /// <param name="recordType">content type used in the record for this message.</param>
        /// <param name="recordVersion"><see cref="ProtocolVersion"/> used for the record.</param>
        /// <param name="ciphertext">array holding input ciphertext to the cipher.</param>
        /// <param name="offset">offset into input array the ciphertext starts at.</param>
        /// <param name="len">length of the ciphertext in the array.</param>
        /// <returns>A <see cref="TlsDecodeResult"/> containing the result of decoding.</returns>
        /// <exception cref="IOException"/>
        TlsDecodeResult DecodeCiphertext(long seqNo, short recordType, ProtocolVersion recordVersion,
            byte[] ciphertext, int offset, int len);

        /// <exception cref="IOException"/>
        void RekeyDecoder();

        /// <exception cref="IOException"/>
        void RekeyEncoder();

        // TODO[api] Separate methods for decode, encode
        bool UsesOpaqueRecordType { get; }
    }
}
