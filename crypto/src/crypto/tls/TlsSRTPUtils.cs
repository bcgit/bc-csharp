using System.Collections;
using System;
using System.IO;
namespace Org.BouncyCastle.Crypto.Tls {

/**
 * RFC 5764 DTLS Extension to Establish Keys for SRTP.
 */
public class TlsSRTPUtils
{
    public const ExtensionType EXT_use_srtp = ExtensionType.use_srtp;

    public static void AddUseSRTPExtension(IDictionary extensions, UseSRTPData useSRTPData)
    {
        extensions[EXT_use_srtp] = CreateUseSRTPExtension(useSRTPData);
    }

    public static UseSRTPData GetUseSRTPExtension(IDictionary extensions)
    {
        byte[] extensionData = TlsUtilities.GetExtensionData(extensions, EXT_use_srtp);
        return extensionData == null ? null : ReadUseSRTPExtension(extensionData);
    }

    public static byte[] CreateUseSRTPExtension(UseSRTPData useSRTPData)
    {
        if (useSRTPData == null)
        {
            throw new ArgumentException("'useSRTPData' cannot be null");
        }

        MemoryStream buf = new MemoryStream();

        // SRTPProtectionProfiles
        int[] protectionProfiles = useSRTPData.ProtectionProfiles;
        int length = 2 * protectionProfiles.Length;
        TlsUtilities.CheckUint16(length);
        TlsUtilities.WriteUint16(length, buf);
        TlsUtilities.WriteUint16Array(protectionProfiles, buf);

        // srtp_mki
        TlsUtilities.WriteOpaque8(useSRTPData.Mki, buf);

        return buf.ToArray();
    }

    public static UseSRTPData ReadUseSRTPExtension(byte[] extensionData)
    {
        if (extensionData == null)
        {
            throw new ArgumentException("'extensionData' cannot be null");
        }

        MemoryStream buf = new MemoryStream(extensionData);

        // SRTPProtectionProfiles
        int length = TlsUtilities.ReadUint16(buf);
        if (length < 2 || (length & 1) != 0)
        {
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }
        int[] protectionProfiles = TlsUtilities.ReadUint16Array(length / 2, buf);

        // srtp_mki
        byte[] mki = TlsUtilities.ReadOpaque8(buf);

        TlsProtocol.AssertEmpty(buf);

        return new UseSRTPData(protectionProfiles, mki);
    }
}

}