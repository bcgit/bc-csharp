namespace Org.BouncyCastle.Crypto.Tls 
{
    interface DTLSHandshakeRetransmit
    {
        void ReceivedHandshakeRecord(int epoch, byte[] buf, int off, int len);
    }
}
