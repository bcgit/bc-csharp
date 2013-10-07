using System.IO;
using Org.BouncyCastle.Utilities;
using System;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Crypto.Tls {


public class HeartbeatMessage
{
    protected short type;
    protected byte[] payload;
    protected int paddingLength;

    public HeartbeatMessage(short type, byte[] payload, int paddingLength)
    {
        if (!HeartbeatMessageType.isValid(type))
        {
            throw new ArgumentException("'type' is not a valid HeartbeatMessageType value");
        }
        if (payload == null || payload.Length >= (1 << 16))
        {
            throw new ArgumentException("'payload' must have length < 2^16");
        }
        if (paddingLength < 16)
        {
            throw new ArgumentException("'paddingLength' must be at least 16");
        }

        this.type = type;
        this.payload = payload;
        this.paddingLength = paddingLength;
    }

    /**
     * Encode this {@link HeartbeatMessage} to an {@link Stream}.
     * 
     * @param output
     *            the {@link Stream} to encode to.
     * @throws IOException
     */
    public void encode(TlsContext context, Stream output) 
    {
        TlsUtilities.WriteUint8(type, output);

        TlsUtilities.CheckUint16(payload.Length);
        TlsUtilities.WriteUint16(payload.Length, output);
        output.Write(payload, 0, payload.Length);

        byte[] padding = new byte[paddingLength];
        context.SecureRandom.NextBytes(padding);
        output.Write(padding, 0, padding.Length);
    }

    /**
     * Parse a {@link HeartbeatMessage} from an {@link InputStream}.
     * 
     * @param input
     *            the {@link InputStream} to parse from.
     * @return a {@link HeartbeatMessage} object.
     * @throws IOException
     */
    public static HeartbeatMessage parse(Stream input) 
    {
        short type = TlsUtilities.ReadUint8(input);
        if (!HeartbeatMessageType.isValid(type))
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }

        int payload_length = TlsUtilities.ReadUint16(input);

        PayloadBuffer buf = new PayloadBuffer();
        Streams.PipeAll(input, buf);

        byte[] payload = buf.ToTruncatedByteArray(payload_length);
        if (payload == null)
        {
            /*
             * RFC 6520 4. If the payload_length of a received HeartbeatMessage is too large, the
             * received HeartbeatMessage MUST be discarded silently.
             */
            return null;
        }

        int padding_length = (int)(buf.Length - payload.Length);

        return new HeartbeatMessage(type, payload, padding_length);
    }

    class PayloadBuffer : MemoryStream
    {
        public byte[] ToTruncatedByteArray(int payloadLength)
        {
            /*
             * RFC 6520 4. The padding_length MUST be at least 16.
             */
            int minimumCount = payloadLength + 16;

            if (this.Length < minimumCount)
            {
                return null;
            }
            return Arrays.CopyOfRange(this.GetBuffer(), 0, payloadLength);
        }
    }
}

}