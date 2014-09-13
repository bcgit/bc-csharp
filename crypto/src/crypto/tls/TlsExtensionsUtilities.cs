﻿using System;
using System.Collections;
using System.IO;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Tls
{
    public abstract class TlsExtensionsUtilities
    {
        public static IDictionary EnsureExtensionsInitialised(IDictionary extensions)
        {
            return extensions == null ? Platform.CreateHashtable() : extensions;
        }

        public static void AddEncryptThenMacExtension(IDictionary extensions)
        {
            extensions[ExtensionType.encrypt_then_mac] = CreateEncryptThenMacExtension();
        }

        public static void AddExtendedMasterSecretExtension(IDictionary extensions)
        {
            extensions[ExtensionType.extended_master_secret] = CreateExtendedMasterSecretExtension();
        }

        /// <exception cref="IOException"></exception>
        public static void AddHeartbeatExtension(IDictionary extensions, HeartbeatExtension heartbeatExtension)
        {
            extensions[ExtensionType.heartbeat] = CreateHeartbeatExtension(heartbeatExtension);
        }

        /// <exception cref="IOException"></exception>
        public static void AddMaxFragmentLengthExtension(IDictionary extensions, byte maxFragmentLength)
        {
            extensions[ExtensionType.max_fragment_length] = CreateMaxFragmentLengthExtension(maxFragmentLength);
        }

        /// <exception cref="IOException"></exception>
        public static void AddServerNameExtension(IDictionary extensions, ServerNameList serverNameList)
        {
            extensions[ExtensionType.server_name] = CreateServerNameExtension(serverNameList);
        }

        /// <exception cref="IOException"></exception>
        public static void AddStatusRequestExtension(IDictionary extensions, CertificateStatusRequest statusRequest)
        {
            extensions[ExtensionType.status_request] = CreateStatusRequestExtension(statusRequest);
        }

        public static void AddTruncatedHMacExtension(IDictionary extensions)
        {
            extensions[ExtensionType.truncated_hmac] = CreateTruncatedHMacExtension();
        }

        /// <exception cref="IOException"></exception>
        public static HeartbeatExtension GetHeartbeatExtension(IDictionary extensions)
        {
            byte[] extensionData = TlsUtilities.GetExtensionData(extensions, ExtensionType.heartbeat);
            return extensionData == null ? null : ReadHeartbeatExtension(extensionData);
        }

        /// <exception cref="IOException"></exception>
        public static short GetMaxFragmentLengthExtension(IDictionary extensions)
        {
            byte[] extensionData = TlsUtilities.GetExtensionData(extensions, ExtensionType.max_fragment_length);
            return extensionData == null ? (short)-1 : (short)ReadMaxFragmentLengthExtension(extensionData);
        }

        /// <exception cref="IOException"></exception>
        public static ServerNameList GetServerNameExtension(IDictionary extensions)
        {
            byte[] extensionData = TlsUtilities.GetExtensionData(extensions, ExtensionType.server_name);
            return extensionData == null ? null : ReadServerNameExtension(extensionData);
        }

        /// <exception cref="IOException"></exception>
        public static CertificateStatusRequest GetStatusRequestExtension(IDictionary extensions)
        {
            byte[] extensionData = TlsUtilities.GetExtensionData(extensions, ExtensionType.status_request);
            return extensionData == null ? null : ReadStatusRequestExtension(extensionData);
        }

        /// <exception cref="IOException"></exception>
        public static bool HasEncryptThenMacExtension(IDictionary extensions)
        {
            byte[] extensionData = TlsUtilities.GetExtensionData(extensions, ExtensionType.encrypt_then_mac);
            return extensionData == null ? false : ReadEncryptThenMacExtension(extensionData);
        }

        /// <exception cref="IOException"></exception>
        public static bool HasExtendedMasterSecretExtension(IDictionary extensions)
        {
            byte[] extensionData = TlsUtilities.GetExtensionData(extensions, ExtensionType.extended_master_secret);
            return extensionData == null ? false : ReadExtendedMasterSecretExtension(extensionData);
        }

        /// <exception cref="IOException"></exception>
        public static bool HasTruncatedHMacExtension(IDictionary extensions)
        {
            byte[] extensionData = TlsUtilities.GetExtensionData(extensions, ExtensionType.truncated_hmac);
            return extensionData == null ? false : ReadTruncatedHMacExtension(extensionData);
        }

        public static byte[] CreateEmptyExtensionData()
        {
            return TlsUtilities.EmptyBytes;
        }

        public static byte[] CreateEncryptThenMacExtension()
        {
            return CreateEmptyExtensionData();
        }

        public static byte[] CreateExtendedMasterSecretExtension()
        {
            return CreateEmptyExtensionData();
        }

        /// <exception cref="IOException"></exception>
        public static byte[] CreateHeartbeatExtension(HeartbeatExtension heartbeatExtension)
        {
            if (heartbeatExtension == null)
                throw new TlsFatalAlert(AlertDescription.internal_error);

            MemoryStream buf = new MemoryStream();

            heartbeatExtension.Encode(buf);

            return buf.ToArray();
        }

        /// <exception cref="IOException"></exception>
        public static byte[] CreateMaxFragmentLengthExtension(byte maxFragmentLength)
        {
            return new byte[]{ maxFragmentLength };
        }

        /// <exception cref="IOException"></exception>
        public static byte[] CreateServerNameExtension(ServerNameList serverNameList)
        {
            if (serverNameList == null)
                throw new TlsFatalAlert(AlertDescription.internal_error);

            MemoryStream buf = new MemoryStream();
        
            serverNameList.Encode(buf);

            return buf.ToArray();
        }

        /// <exception cref="IOException"></exception>
        public static byte[] CreateStatusRequestExtension(CertificateStatusRequest statusRequest)
        {
            if (statusRequest == null)
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }

            MemoryStream buf = new MemoryStream();

            statusRequest.Encode(buf);

            return buf.ToArray();
        }

        public static byte[] CreateTruncatedHMacExtension()
        {
            return CreateEmptyExtensionData();
        }

        /// <exception cref="IOException"></exception>
        private static bool ReadEmptyExtensionData(byte[] extensionData)
        {
            if (extensionData == null)
                throw new ArgumentNullException("extensionData");

            if (extensionData.Length != 0)
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);

            return true;
        }

        /// <exception cref="IOException"></exception>
        public static bool ReadEncryptThenMacExtension(byte[] extensionData)
        {
            return ReadEmptyExtensionData(extensionData);
        }

        /// <exception cref="IOException"></exception>
        public static bool ReadExtendedMasterSecretExtension(byte[] extensionData)
        {
            return ReadEmptyExtensionData(extensionData);
        }

        /// <exception cref="IOException"></exception>
        public static HeartbeatExtension ReadHeartbeatExtension(byte[] extensionData)
        {
            if (extensionData == null)
                throw new ArgumentNullException("extensionData");

            MemoryStream buf = new MemoryStream(extensionData, false);

            HeartbeatExtension heartbeatExtension = HeartbeatExtension.Parse(buf);

            TlsProtocol.AssertEmpty(buf);

            return heartbeatExtension;
        }

        /// <exception cref="IOException"></exception>
        public static short ReadMaxFragmentLengthExtension(byte[] extensionData)
        {
            if (extensionData == null)
                throw new ArgumentNullException("extensionData");

            if (extensionData.Length != 1)
                throw new TlsFatalAlert(AlertDescription.decode_error);

            return extensionData[0];
        }

        /// <exception cref="IOException"></exception>
        public static ServerNameList ReadServerNameExtension(byte[] extensionData)
        {
            if (extensionData == null)
                throw new ArgumentNullException("extensionData");

            MemoryStream buf = new MemoryStream(extensionData, false);

            ServerNameList serverNameList = ServerNameList.Parse(buf);

            TlsProtocol.AssertEmpty(buf);

            return serverNameList;
        }

        /// <exception cref="IOException"></exception>
        public static CertificateStatusRequest ReadStatusRequestExtension(byte[] extensionData)
        {
            if (extensionData == null)
                throw new ArgumentNullException("extensionData");

            MemoryStream buf = new MemoryStream(extensionData, false);

            CertificateStatusRequest statusRequest = CertificateStatusRequest.Parse(buf);

            TlsProtocol.AssertEmpty(buf);

            return statusRequest;
        }

        /// <exception cref="IOException"></exception>
        public static bool ReadTruncatedHMacExtension(byte[] extensionData)
        {
            return ReadEmptyExtensionData(extensionData);
        }
    }
}
