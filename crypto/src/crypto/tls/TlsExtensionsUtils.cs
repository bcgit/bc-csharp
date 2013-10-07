using System.Collections;
using System.IO;
using System;

namespace Org.BouncyCastle.Crypto.Tls 
{

public class TlsExtensionsUtils
{
    public static readonly ExtensionType EXT_heartbeat = ExtensionType.heartbeat;
    public static readonly ExtensionType EXT_max_fragment_length = ExtensionType.max_fragment_length;
    public static readonly ExtensionType EXT_server_name = ExtensionType.server_name;
    public static readonly ExtensionType EXT_status_request = ExtensionType.status_request;
    public static readonly ExtensionType EXT_truncated_hmac = ExtensionType.truncated_hmac;

    public static IDictionary EnsureExtensionsInitialised(IDictionary extensions)
    {
        return extensions == null ? new Hashtable() : extensions;
    }
    public static void AddHeartbeatExtension(IDictionary extensions, HeartbeatExtension heartbeatExtension)
    {
        extensions[EXT_heartbeat] =  CreateHeartbeatExtension(heartbeatExtension);
    }

    public static void AddMaxFragmentLengthExtension(IDictionary extensions, short maxFragmentLength)
    {
        extensions[EXT_max_fragment_length] = createMaxFragmentLengthExtension(maxFragmentLength);
    }

    public static void AddServerNameExtension(IDictionary extensions, ServerNameList serverNameList)
    {
        extensions[EXT_server_name] = createServerNameExtension(serverNameList);
    }

    public static void AddStatusRequestExtension(IDictionary extensions, CertificateStatusRequest statusRequest)
    {
        extensions[EXT_status_request] = createStatusRequestExtension(statusRequest);
    }

    public static void AddTruncatedHMacExtension(IDictionary extensions)
    {
        extensions[EXT_truncated_hmac] = createTruncatedHMacExtension();
    }

    public static HeartbeatExtension GetHeartbeatExtension(IDictionary extensions)
    {
        byte[] extensionData = TlsUtilities.GetExtensionData(extensions, EXT_heartbeat);
        return extensionData == null ? null : readHeartbeatExtension(extensionData);
    }

    public static short GetMaxFragmentLengthExtension(IDictionary extensions)
    {
        byte[] extensionData = TlsUtilities.GetExtensionData(extensions, EXT_max_fragment_length);
        return (short)( extensionData == null ? -1 : readMaxFragmentLengthExtension(extensionData));
    }

    public static ServerNameList GetServerNameExtension(IDictionary extensions)
    {
        byte[] extensionData = TlsUtilities.GetExtensionData(extensions, EXT_server_name);
        return extensionData == null ? null : readServerNameExtension(extensionData);
    }

    public static CertificateStatusRequest GetStatusRequestExtension(IDictionary extensions)
    {
        byte[] extensionData = TlsUtilities.GetExtensionData(extensions, EXT_status_request);
        return extensionData == null ? null : readStatusRequestExtension(extensionData);
    }

    public static bool HasTruncatedHMacExtension(IDictionary extensions) 
    {
        byte[] extensionData = TlsUtilities.GetExtensionData(extensions, EXT_truncated_hmac);
        return extensionData == null ? false : readTruncatedHMacExtension(extensionData);
    }

    public static byte[] CreateEmptyExtensionData()
    {
        return TlsUtilities.EMPTY_BYTES;
    }

    public static byte[] CreateHeartbeatExtension(HeartbeatExtension heartbeatExtension)
    {
        if (heartbeatExtension == null)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        MemoryStream buf = new MemoryStream();

        heartbeatExtension.encode(buf);

        return buf.ToArray();
    }

    public static byte[] createMaxFragmentLengthExtension(short maxFragmentLength)
    {
        if (!MaxFragmentLength.IsValid(maxFragmentLength))
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        return new byte[]{ (byte)maxFragmentLength };
    }

    public static byte[] createServerNameExtension(ServerNameList serverNameList)
    {
        if (serverNameList == null)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
        
        MemoryStream buf = new MemoryStream();
        
        serverNameList.Encode(buf);

        return buf.ToArray();
    }

    public static byte[] createStatusRequestExtension(CertificateStatusRequest statusRequest)
    {
        if (statusRequest == null)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        MemoryStream buf = new MemoryStream();

        statusRequest.encode(buf);

        return buf.ToArray();
    }

    public static byte[] createTruncatedHMacExtension()
    {
        return CreateEmptyExtensionData();
    }

    public static HeartbeatExtension readHeartbeatExtension(byte[] extensionData)        
    {
        if (extensionData == null)
        {
            throw new ArgumentException("'extensionData' cannot be null");
        }

        MemoryStream buf = new MemoryStream(extensionData);

        HeartbeatExtension heartbeatExtension = HeartbeatExtension.parse(buf);

        TlsProtocol.AssertEmpty(buf);

        return heartbeatExtension;
    }

    public static short readMaxFragmentLengthExtension(byte[] extensionData)        
    {
        if (extensionData == null)
        {
            throw new ArgumentException("'extensionData' cannot be null");
        }

        if (extensionData.Length != 1)
        {
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }

        short maxFragmentLength = (short)extensionData[0];

        if (!MaxFragmentLength.IsValid(maxFragmentLength))
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }

        return maxFragmentLength;
    }

    public static ServerNameList readServerNameExtension(byte[] extensionData)        
    {
        if (extensionData == null)
        {
            throw new ArgumentException("'extensionData' cannot be null");
        }

        MemoryStream buf = new MemoryStream(extensionData);

        ServerNameList serverNameList = ServerNameList.Parse(buf);

        TlsProtocol.AssertEmpty(buf);

        return serverNameList;
    }

    public static CertificateStatusRequest readStatusRequestExtension(byte[] extensionData)        
    {
        if (extensionData == null)
        {
            throw new ArgumentException("'extensionData' cannot be null");
        }

        MemoryStream buf = new MemoryStream(extensionData);

        CertificateStatusRequest statusRequest = CertificateStatusRequest.parse(buf);

        TlsProtocol.AssertEmpty(buf);

        return statusRequest;
    }

    private static bool readTruncatedHMacExtension(byte[] extensionData) 
    {
        if (extensionData == null)
        {
            throw new ArgumentException("'extensionData' cannot be null");
        }

        if (extensionData.Length != 0)
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }

        return true;
    }
}

}