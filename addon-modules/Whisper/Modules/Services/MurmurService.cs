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

namespace Aurora.Voice.Whisper
{
    public class MurmurService : IMurmurService, IService
    {
        private IConfig m_config;

        public void Initialize(IConfigSource config, IRegistryCore registry)
        {
            m_config = config.Configs["MurmurService"];
            if (m_config != null)
                registry.RegisterModuleInterface<IMurmurService>(this);
        }

        public void Start(IConfigSource config, IRegistryCore registry)
        {
        }

        public void FinishedStartup()
        {
        }

        public MurmurConfig GetConfiguration(string regionName)
        {
            MurmurConfig config = new MurmurConfig();

            // retrieve configuration variables
            config.MetaIce = "Meta:" + m_config.GetString("murmur_ice", String.Empty);
            config.MurmurHost = m_config.GetString("murmur_host", String.Empty);
            config.ServerID = m_config.GetInt("murmur_sid", 1);
            config.ServerVersion = m_config.GetString("server_version", String.Empty);

            config.GlacierEnabled = m_config.GetBoolean("glacier", false);

            config.GlacierIce = m_config.GetString("glacier_ice", String.Empty);
            config.GlacierUser = m_config.GetString("glacier_user", "admin");
            config.GlacierPass = m_config.GetString("glacier_pass", "password");

            config.IceCB = m_config.GetString("murmur_ice_cb", "tcp -h 127.0.0.1");

            if (m_config.GetBoolean("use_one_channel", false))
                config.ChannelName = m_config.GetString("channel_name", "Channel");
            else
                config.ChannelName = regionName;

            return config;
        }
    }
}
