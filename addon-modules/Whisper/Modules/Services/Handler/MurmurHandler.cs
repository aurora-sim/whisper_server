﻿using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Text;
using log4net;
using Nini.Config;
using Aurora.Simulation.Base;
using OpenSim.Services.Interfaces;
using OpenSim.Framework;
using OpenSim.Framework.Servers.HttpServer;
using OpenMetaverse;
using OpenMetaverse.StructuredData;
using Aurora.DataManager;
using Aurora.Framework;

namespace Aurora.Voice.Whisper
{
    public class MurmurHandler : IService, IGridRegistrationUrlModule
    {
        #region IService Members

        private IRegistryCore m_registry;
        private uint m_port = 0;

        public string Name
        {
            get { return GetType().Name; }
        }

        public void Initialize(IConfigSource config, IRegistryCore registry)
        {
        }

        public void Start(IConfigSource config, IRegistryCore registry)
        {
            IConfig handlerConfig = config.Configs["MurmurService"];
            if (handlerConfig == null || handlerConfig.GetString("MurmurHandler", "") != Name)
                return;

            m_registry = registry;
            m_port = handlerConfig.GetUInt("MurmurInHandlerPort");

            if (handlerConfig.GetBoolean("UnsecureUrls", false))
            {
                string url = "/MURMUR";

                IHttpServer server = registry.RequestModuleInterface<ISimulationBase>().GetHttpServer(m_port);
                m_port = server.Port;

                server.AddStreamHandler(new MurmurPoster(url, registry.RequestModuleInterface<IMurmurService>(),
                0, m_registry));
            }
            m_registry.RequestModuleInterface<IGridRegistrationService>().RegisterModule(this);
        }

        public void FinishedStartup()
        {
        }

        #endregion

        #region IGridRegistrationUrlModule Members

        public string UrlName
        {
            get { return "MurmurServiceURI"; }
        }

        public uint Port
        {
            get { return m_port; }
        }

        public void AddExistingUrlForClient(string SessionID, ulong RegionHandle, string url)
        {
            IHttpServer server = m_registry.RequestModuleInterface<ISimulationBase>().GetHttpServer(m_port);
            m_port = server.Port;

            server.AddStreamHandler(new MurmurPoster(url, m_registry.RequestModuleInterface<IMurmurService>(),
                    RegionHandle, m_registry));
        }

        public string GetUrlForRegisteringClient(string SessionID, ulong RegionHandle)
        {
            string url = "/MURMUR" + UUID.Random();

            IHttpServer server = m_registry.RequestModuleInterface<ISimulationBase>().GetHttpServer(m_port);
            m_port = server.Port;

            server.AddStreamHandler(new MurmurPoster(url, m_registry.RequestModuleInterface<IMurmurService>(),
                    RegionHandle, m_registry));
            return url;
        }

        #endregion
    }

    public class MurmurPoster : BaseStreamHandler
    {
        private static readonly ILog m_log = LogManager.GetLogger(MethodBase.GetCurrentMethod().DeclaringType);

        private IMurmurService m_service;
        private ulong m_ourRegionHandle;
        protected IRegistryCore m_registry;

        public MurmurPoster(string url, IMurmurService handler, ulong handle, IRegistryCore registry) :
            base("POST", url)
        {
            m_service = handler;
            m_ourRegionHandle = handle;
            m_registry = registry;
        }

        public override byte[] Handle(string path, Stream requestData,
                OSHttpRequest httpRequest, OSHttpResponse httpResponse)
        {
            StreamReader sr = new StreamReader(requestData);
            string body = sr.ReadToEnd();
            sr.Close();
            body = body.Trim();

            IGridRegistrationService urlModule =
                            m_registry.RequestModuleInterface<IGridRegistrationService>();
            if (urlModule != null)
                if (!urlModule.CheckThreatLevel("", m_ourRegionHandle, "Murmur_Get", ThreatLevel.None))
                    return new byte[0];

            OSDMap request = WebUtils.GetOSDMap(body);
            if (request == null)
                return null;

            return ProcessGet(request);
        }

        private byte[] ProcessGet(OSDMap request)
        {
            string regionName = request["RegionName"];
            MurmurConfig config = m_service.GetConfiguration(regionName);
            OSDMap response = config.ToOSD();
            string resp = OSDParser.SerializeJsonString(response);
            if (resp == "")
                return new byte[0];
            return Util.UTF8.GetBytes(resp);
        }
    }
}
