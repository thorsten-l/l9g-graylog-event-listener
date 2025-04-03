package l9g.keycloak.graylog;

import org.keycloak.Config;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventListenerProviderFactory;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public class GraylogUdpEventListenerFactory implements
  EventListenerProviderFactory
{
  private static final Logger logger =
    Logger.getLogger(GraylogUdpEventListenerFactory.class);

  private String hostname = "keycloak";

  private String gelfHost = "127.0.0.1";

  private int gelfPort = 12201;

  @Override
  public EventListenerProvider create(KeycloakSession session)
  {
    try
    {
      return new GraylogUdpEventListener(session, hostname, gelfHost, gelfPort);
    }
    catch(Exception e)
    {
      logger.error("Fehler beim Initialisieren des GraylogUdpEventListener", e);
      throw new RuntimeException(e);
    }
  }

  @Override
  public void init(Config.Scope config)
  {
    if(config.get("hostname") != null)
    {
      hostname = config.get("hostname");
    }

    if(config.get("gelf-host") != null)
    {
      gelfHost = config.get("gelf-host");
    }

    if(config.get("gelf-port") != null)
    {
      gelfPort = config.getInt("gelf-port", 12201);
    }
    
    logger.infof("gelf source = %s", hostname);
    logger.infof("gelf address = %s:%d", gelfHost, gelfPort);
  }

  @Override
  public void postInit(KeycloakSessionFactory factory)
  {
    //
  }

  @Override
  public void close()
  {
  }

  @Override
  public String getId()
  {
    return "l9g-graylog";
  }

}
