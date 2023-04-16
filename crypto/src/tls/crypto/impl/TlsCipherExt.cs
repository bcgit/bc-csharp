namespace Org.BouncyCastle.Tls.Crypto
{
    // TODO[api] Merge into TlsCipher
    public interface TlsCipherExt
    {
        int GetPlaintextDecodeLimit(int ciphertextLimit);

        int GetPlaintextEncodeLimit(int ciphertextLimit);
    }
}
