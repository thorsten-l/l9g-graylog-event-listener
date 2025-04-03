package l9g.keycloak.graylog;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import org.keycloak.events.Event;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.events.EventListenerProvider;
import org.jboss.logging.Logger;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.HashMap;
import java.util.Map;
import org.keycloak.models.KeycloakSession;
import org.keycloak.sessions.AuthenticationSessionModel;

public class GraylogUdpEventListener implements EventListenerProvider
{
  private static final Logger logger =
    Logger.getLogger(GraylogUdpEventListener.class);

  private final KeycloakSession session;

  private final String hostname;

  private final String gelfHost;

  private final int gelfPort;

  private final DatagramSocket socket;

  private final ObjectMapper objectMapper = new ObjectMapper();

  public GraylogUdpEventListener(
    KeycloakSession session, String hostname, String gelfHost, int gelfPort)
    throws Exception
  {
    this.session = session;
    this.hostname = hostname;
    this.gelfHost = gelfHost;
    this.gelfPort = gelfPort;
    this.socket = new DatagramSocket();
  }

  @Override
  public void onEvent(Event event)
  {
    String gelfMsg = createGelfMessage(event);
    sendGelfMessage(gelfMsg);
  }

  @Override
  public void onEvent(AdminEvent adminEvent, boolean includeRepresentation)
  {
    String gelfMsg = createGelfMessage(adminEvent);
    sendGelfMessage(gelfMsg);
  }

  @Override
  public void close()
  {
    socket.close();
  }

  private void include(
    Map<String, Object> msg, StringBuilder shortMessage,
    String name, String value)
  {
    if(value != null)
    {
      shortMessage.append(" ");
      shortMessage.append(value);
      msg.put(name, value);
    }
  }

  private String createGelfMessage(Event event)
  {
    try
    {
      Map<String, Object> msg = new HashMap<>();

      StringBuilder shortMessage =
        new StringBuilder(String.valueOf(event.getType()));
      
      include(msg, shortMessage, "ip_address", event.getIpAddress());
      include(msg, shortMessage, "realm_name", event.getRealmName());
      include(msg, shortMessage, "client_id", event.getClientId());
      include(msg, shortMessage, "user_id", event.getUserId());
      include(msg, shortMessage, "username", event.getDetails().get("username"));
      include(msg, shortMessage, "sesson_id", event.getSessionId());
      include(msg, shortMessage, "error", event.getError());

      msg.put("version", "1.1");
      msg.put("host", hostname);
      msg.put("event_id", event.getId());
      msg.put("short_message", shortMessage.toString());
      msg.put("timestamp", event.getTime() / 1000l);
      msg.put("realm_id", event.getRealmId());
      msg.put("event_type", event.getType());

      if(event.getDetails() != null &&  ! event.getDetails().isEmpty())
      {
        msg.putAll(event.getDetails());
      }

      AuthenticationSessionModel authSession =
        session.getContext().getAuthenticationSession();
      if(authSession != null)
      {
        msg.put("auth_session_parent_id", authSession.getParentSession().getId());
        msg.put("auth_session_tab_id", authSession.getTabId());
      }

      String gelfMessage = objectMapper.writeValueAsString(msg);
      logger.debugf("event=%s", gelfMessage);
      return gelfMessage;
    }
    catch(Throwable t)
    {
      logger.error("Fehler beim Erstellen der GELF-Nachricht", t);
      return "";
    }
  }

  private String createGelfMessage(AdminEvent adminEvent)
  {
    try
    {
      Map<String, Object> msg = new HashMap<>();
      StringBuilder shortMessage =
        new StringBuilder(String.valueOf(adminEvent.getOperationType()));

      shortMessage.append(" ");
      shortMessage.append(adminEvent.getError());

      if(adminEvent.getError() != null)
      {
        msg.put("error", adminEvent.getError());
        shortMessage.append(" ");
        shortMessage.append(adminEvent.getError());
      }

      msg.put("version", "1.1");
      msg.put("event_id", adminEvent.getId());
      msg.put("admin_event", "true");
      msg.put("host", hostname);
      msg.put("short_message", shortMessage);
      msg.put("operation_type", String.valueOf(adminEvent.getOperationType()));
      msg.put("timestamp", (System.currentTimeMillis() / 1000l));
      msg.put("resource_path", adminEvent.getResourcePath());
      msg.put("resource_type", adminEvent.getResourceTypeAsString());
      msg.put("representation", adminEvent.getRepresentation());

      msg.put("realm_id", adminEvent.getAuthDetails().getRealmId());
      msg.put("realm_name", adminEvent.getAuthDetails().getRealmName());
      msg.put("client_id", adminEvent.getAuthDetails().getClientId());
      msg.put("user_id", adminEvent.getAuthDetails().getUserId());
      msg.put("ip_address", adminEvent.getAuthDetails().getIpAddress());

      if(adminEvent.getDetails() != null
        &&  ! adminEvent.getDetails().isEmpty())
      {
        msg.putAll(adminEvent.getDetails());
      }
      String gelfMessage = objectMapper.writeValueAsString(msg);
      logger.debugf("admin event=%s", gelfMessage);
      return gelfMessage;
    }
    catch(Throwable t)
    {
      logger.error("Fehler beim Erstellen der GELF-Nachricht für AdminEvent", t);
      return "";
    }
  }

  private void sendGelfMessage(String gelfJson)
  {
    if(gelfJson == null || gelfJson.isEmpty())
    {
      return;
    }
    try
    {
      byte[] data = gelfJson.getBytes("UTF-8");
      InetAddress address = InetAddress.getByName(gelfHost);
      DatagramPacket packet = new DatagramPacket(data, data.length, address, gelfPort);
      socket.send(packet);
    }
    catch(Exception e)
    {
      logger.error("Fehler beim Senden der GELF-Lognachricht", e);
    }
  }

}
