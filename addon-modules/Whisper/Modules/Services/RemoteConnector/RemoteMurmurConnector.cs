using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Nini.Config;
using Aurora.Simulation.Base;
using log4net;
using OpenSim.Framework;
using OpenMetaverse;
using OpenMetaverse.StructuredData;
using OpenSim.Services.Interfaces;

namespace Aurora.Voice.Whisper
{
    public class RemoteMurmurConnector : IService, IMurmurService
    {
        private IRegistryCore m_registry;

        public void Initialize(IConfigSource config, IRegistryCore registry)
        {
            m_registry = registry;
            IConfig m_config = config.Configs["MurmurService"];
            if (m_config != null)
            {
                bool enabled = m_config.GetString("MurmurService") == GetType().Name;
                if (enabled)
                    registry.RegisterModuleInterface<IMurmurService>(this);
            }
        }

        public void Start(IConfigSource config, IRegistryCore registry)
        {
        }

        public void FinishedStartup()
        {
        }

        public MurmurConfig GetConfiguration(string regionName)
        {
            IConfigurationService service = m_registry.RequestModuleInterface<IConfigurationService>();
            if (service == null)
                return null;
            List<string> urls = service.FindValueOf("MurmurServiceURI");
            foreach (string url in urls)
            {
                OSDMap request = new OSDMap();
                request["RegionName"] = regionName;
                OSDMap response = WebUtils.PostToService (url, request, true, true);
                OSDMap resp = (OSDMap)response["_Result"];
                if (resp.Type == OSDType.Unknown) //Make sure we got back a good response
                    return null;
                //Now parse from OSD
                MurmurConfig config = new MurmurConfig();
                config.FromOSD(resp);
                return config;
            }
            return null;
        }
    }
}
