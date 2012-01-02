using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Text;
using Aurora.Framework.Servers.HttpServer;
using log4net;
using Nini.Config;
using Aurora.Simulation.Base;
using OpenSim.Services.Interfaces;
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

        public void AddExistingUrlForClient (string SessionID, string url, uint port)
        {
            IHttpServer server = m_registry.RequestModuleInterface<ISimulationBase>().GetHttpServer(port);

            server.AddStreamHandler(new MurmurPoster(url, m_registry.RequestModuleInterface<IMurmurService>(),
                    SessionID, m_registry));
        }

        public string GetUrlForRegisteringClient (string SessionID, uint port)
        {
            string url = "/MURMUR" + UUID.Random();

            IHttpServer server = m_registry.RequestModuleInterface<ISimulationBase>().GetHttpServer(port);

            server.AddStreamHandler(new MurmurPoster(url, m_registry.RequestModuleInterface<IMurmurService>(),
                    SessionID, m_registry));
            return url;
        }

        public void RemoveUrlForClient (string sessionID, string url, uint port)
        {
            IHttpServer server = m_registry.RequestModuleInterface<ISimulationBase>().GetHttpServer(port);
            server.RemoveHTTPHandler("POST", url);
        }

        #endregion
    }

    public class MurmurPoster : BaseStreamHandler
    {
        private readonly IMurmurService m_service;
        private readonly string m_SessionID;
        protected IRegistryCore m_registry;

        public MurmurPoster (string url, IMurmurService handler, string SessionID, IRegistryCore registry) :
            base("POST", url)
        {
            m_service = handler;
            m_SessionID = SessionID;
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
                if (!urlModule.CheckThreatLevel (m_SessionID, "Murmur_Get", ThreatLevel.None))
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
