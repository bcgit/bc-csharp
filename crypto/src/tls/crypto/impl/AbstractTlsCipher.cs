using System;

using Org.BouncyCastle.Utilities.IO.Compression;

namespace Org.BouncyCastle.Tls.Crypto.Impl
{
    public abstract class AbstractTlsCipher
        : TlsCipher
    {
        public abstract int GetCiphertextDecodeLimit(int plaintextLimit);

        public abstract int GetCiphertextEncodeLimit(int plaintextLength, int plaintextLimit);

        // TODO[api] Remove this method from TlsCipher
        public virtual int GetPlaintextLimit(int ciphertextLimit)
        {
            return GetPlaintextEncodeLimit(ciphertextLimit);
        }

        // TODO[api] Add to TlsCipher
        public virtual int GetPlaintextDecodeLimit(int ciphertextLimit)
        {
            return GetPlaintextLimit(ciphertextLimit);
        }

        // TODO[api] Add to TlsCipher
        public virtual int GetPlaintextEncodeLimit(int ciphertextLimit)
        {
            return GetPlaintextLimit(ciphertextLimit);
        }

        public abstract TlsEncodeResult EncodePlaintext(long seqNo, short contentType, ProtocolVersion recordVersion,
            int headerAllocation, byte[] plaintext, int offset, int len);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public abstract TlsEncodeResult EncodePlaintext(long seqNo, short contentType, ProtocolVersion recordVersion,
            int headerAllocation, ReadOnlySpan<byte> plaintext);
#endif

        // TODO[api] Add span-based version?
        public abstract TlsDecodeResult DecodeCiphertext(long seqNo, short recordType, ProtocolVersion recordVersion,
            byte[] ciphertext, int offset, int len);

        public virtual void RekeyDecoder()
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        public virtual void RekeyEncoder()
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        public abstract bool UsesOpaqueRecordType { get; }
    }
}
