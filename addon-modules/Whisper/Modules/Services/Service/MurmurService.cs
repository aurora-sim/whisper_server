using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Aurora.Framework;
using Nini.Config;
using Aurora.Simulation.Base;
using log4net;
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
            {
                bool enabled = m_config.GetString("MurmurService") == GetType().Name;
                if(enabled)
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
            MurmurConfig config = new MurmurConfig
                                      {
                                          MetaIce = "Meta:" + m_config.GetString("murmur_ice", String.Empty),
                                          MurmurHost = m_config.GetString("murmur_host", String.Empty),
                                          ServerID = m_config.GetInt("murmur_sid", 1),
                                          ServerVersion = m_config.GetString("server_version", String.Empty),
                                          GlacierEnabled = m_config.GetBoolean("glacier", false),
                                          GlacierIce = m_config.GetString("glacier_ice", String.Empty),
                                          GlacierUser = m_config.GetString("glacier_user", "admin"),
                                          GlacierPass = m_config.GetString("glacier_pass", "password"),
                                          IceCB = m_config.GetString("murmur_ice_cb", "tcp -h 127.0.0.1"),
                                          ChannelName =
                                              m_config.GetBoolean("use_one_channel", false)
                                                  ? m_config.GetString("channel_name", "Channel")
                                                  : regionName
                                      };

            // retrieve configuration variables





            return config;
        }
    }
}
