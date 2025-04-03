/*
 * Copyright 2025 Thorsten Ludewig (t.ludewig@gmail.com).
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 *
 * GraylogUdpEventListener
 *
 * This class implements the `EventListenerProvider` interface from Keycloak
 * and is responsible for sending Keycloak events and admin events to a Graylog server
 * using the GELF (Graylog Extended Log Format) protocol over UDP.
 *
 * Author: Thorsten Ludewig (t.ludewig@gmail.com)
 * License: Apache License, Version 2.0
 */
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

  // Logger instance for logging messages
  private static final Logger logger = Logger.getLogger(GraylogUdpEventListener.class);

  // Keycloak session object
  private final KeycloakSession session;

  // Hostname of the GELF source
  private final String hostname;

  // Graylog server host and port
  private final String gelfHost;

  private final int gelfPort;

  // UDP socket for sending GELF messages
  private final DatagramSocket socket;

  // ObjectMapper for converting objects to JSON
  private final ObjectMapper objectMapper = new ObjectMapper();

  /**
   * Constructor for the GraylogUdpEventListener.
   *
   * @param session The Keycloak session.
   * @param hostname The hostname of the GELF source.
   * @param gelfHost The Graylog server host.
   * @param gelfPort The Graylog server port.
   *
   * @throws Exception If an error occurs while initializing the UDP socket.
   */
  public GraylogUdpEventListener(KeycloakSession session, String hostname, String gelfHost, int gelfPort)
    throws Exception
  {
    this.session = session;
    this.hostname = hostname;
    this.gelfHost = gelfHost;
    this.gelfPort = gelfPort;
    this.socket = new DatagramSocket();
  }

  /**
   * Handles Keycloak events and sends them to Graylog.
   *
   * @param event The Keycloak event to process.
   */
  @Override
  public void onEvent(Event event)
  {
    String gelfMsg = createGelfMessage(event);
    sendGelfMessage(gelfMsg);
  }

  /**
   * Handles Keycloak admin events and sends them to Graylog.
   *
   * @param adminEvent The admin event to process.
   * @param includeRepresentation Whether to include the representation in the message.
   */
  @Override
  public void onEvent(AdminEvent adminEvent, boolean includeRepresentation)
  {
    String gelfMsg = createGelfMessage(adminEvent);
    sendGelfMessage(gelfMsg);
  }

  /**
   * Closes the UDP socket when the listener is no longer needed.
   */
  @Override
  public void close()
  {
    socket.close();
  }

  /**
   * Adds a key-value pair to the GELF message and appends the value to the short message.
   *
   * @param msg The GELF message map.
   * @param shortMessage The short message builder.
   * @param name The key name.
   * @param value The value to add.
   */
  private void include(Map<String, Object> msg, StringBuilder shortMessage, String name, String value)
  {
    if(value != null)
    {
      shortMessage.append(" ");
      shortMessage.append(value);
      msg.put(name, value);
    }
  }

  /**
   * Creates a GELF message from a Keycloak event.
   *
   * @param event The Keycloak event.
   *
   * @return The GELF message as a JSON string.
   */
  private String createGelfMessage(Event event)
  {
    try
    {
      Map<String, Object> msg = new HashMap<>();
      StringBuilder shortMessage = new StringBuilder(String.valueOf(event.getType()));

      // Add event details to the GELF message
      include(msg, shortMessage, "ip_address", event.getIpAddress());
      include(msg, shortMessage, "realm_name", event.getRealmName());
      include(msg, shortMessage, "client_id", event.getClientId());
      include(msg, shortMessage, "user_id", event.getUserId());
      include(msg, shortMessage, "username", event.getDetails().get("username"));
      include(msg, shortMessage, "sesson_id", event.getSessionId());
      include(msg, shortMessage, "error", event.getError());

      // Add standard GELF fields
      msg.put("version", "1.1");
      msg.put("host", hostname);
      msg.put("event_id", event.getId());
      msg.put("short_message", shortMessage.toString());
      msg.put("timestamp", event.getTime() / 1000L);
      msg.put("realm_id", event.getRealmId());
      msg.put("event_type", event.getType());

      // Add additional event details if available
      if(event.getDetails() != null &&  ! event.getDetails().isEmpty())
      {
        msg.putAll(event.getDetails());
      }

      // Add authentication session details if available
      AuthenticationSessionModel authSession = session.getContext().getAuthenticationSession();
      if(authSession != null)
      {
        msg.put("auth_session_parent_id", authSession.getParentSession().getId());
        msg.put("auth_session_tab_id", authSession.getTabId());
      }

      // Convert the message to JSON
      String gelfMessage = objectMapper.writeValueAsString(msg);
      logger.debugf("event=%s", gelfMessage);
      return gelfMessage;
    }
    catch(Throwable t)
    {
      logger.error("Error creating GELF message", t);
      return "";
    }
  }

  /**
   * Creates a GELF message from a Keycloak admin event.
   *
   * @param adminEvent The admin event.
   *
   * @return The GELF message as a JSON string.
   */
  private String createGelfMessage(AdminEvent adminEvent)
  {
    try
    {
      Map<String, Object> msg = new HashMap<>();
      msg.put("version", "1.1");
      msg.put("admin_event", "true");

      StringBuilder shortMessage = new StringBuilder("ADMIN_EVENT ");
      shortMessage.append(String.valueOf(adminEvent.getOperationType()));

      // Add admin event details to the GELF message
      include(msg, shortMessage, "error", adminEvent.getError());
      include(msg, shortMessage, "event_id", adminEvent.getId());
      msg.put("operation_type", String.valueOf(adminEvent.getOperationType()));
      msg.put("resource_path", adminEvent.getResourcePath());
      msg.put("resource_type", adminEvent.getResourceTypeAsString());
      msg.put("representation", adminEvent.getRepresentation());
      msg.put("realm_id", adminEvent.getAuthDetails().getRealmId());
      include(msg, shortMessage, "realm_name", adminEvent.getAuthDetails().getRealmName());
      include(msg, shortMessage, "client_id", adminEvent.getAuthDetails().getClientId());
      include(msg, shortMessage, "user_id", adminEvent.getAuthDetails().getUserId());
      include(msg, shortMessage, "ip_address", adminEvent.getAuthDetails().getIpAddress());

      // Add standard GELF fields
      msg.put("host", hostname);
      msg.put("short_message", shortMessage);
      msg.put("timestamp", (System.currentTimeMillis() / 1000L));

      // Add additional admin event details if available
      if(adminEvent.getDetails() != null &&  ! adminEvent.getDetails().isEmpty())
      {
        msg.putAll(adminEvent.getDetails());
      }

      // Convert the message to JSON
      String gelfMessage = objectMapper.writeValueAsString(msg);
      logger.debugf("admin event=%s", gelfMessage);
      return gelfMessage;
    }
    catch(Throwable t)
    {
      logger.error("Error creating GELF message for AdminEvent", t);
      return "";
    }
  }

  /**
   * Sends a GELF message to the Graylog server.
   *
   * @param gelfJson The GELF message as a JSON string.
   */
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
      logger.error("Error sending GELF log message", e);
    }
  }

}
