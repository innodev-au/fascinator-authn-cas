package au.com.innodev.fascinator.portal.sso.cas;

import java.io.IOException;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.apache.velocity.Template;
import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.Velocity;
import org.jasig.cas.client.util.CommonUtils;
import org.jasig.cas.client.util.ReflectUtils;
import org.jasig.cas.client.validation.Assertion;
import org.jasig.cas.client.validation.Cas10TicketValidator;
import org.jasig.cas.client.validation.TicketValidationException;
import org.jasig.cas.client.validation.TicketValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.googlecode.fascinator.api.authentication.User;
import com.googlecode.fascinator.common.JsonSimpleConfig;
import com.googlecode.fascinator.common.authentication.GenericUser;
import com.googlecode.fascinator.portal.JsonSessionState;
import com.googlecode.fascinator.portal.sso.SSOInterface;

/**
 * CAS authentication integration for The Fascinator.
 * 
 * @author Mike Jones
 */
public class CAS implements SSOInterface {

	public static final String CAS_PLUGIN_ID = "CAS";

	public static final String PROP_CAS_SERVER_URL = "casServerUrl";
	public static final String PROP_SSO_LOGOUT = "ssoLogout";
	public static final String PROP_TICKET_VALIDATOR_CLASS = "ticketValidatorClassName";

	private static final String CAS_TICKET_HTTP_HEADER = "ticket";

	private static final String RETURN_ADDRESS = "cas-return-address";
	private static final String CAS_TICKET = "cas-" + CAS_TICKET_HTTP_HEADER;
	private static final String CAS_USERNAME = "cas-username";

	private static final Logger logger = LoggerFactory.getLogger(CAS.class);

	private String casLoginUrl;					// Login URL of the CAS server, e.g. https://cas.yourdomain.edu.au/login
	private String casLogoutUrl;				// Logout URL of the CAS server, e.g. https://cas.yourdomain.edu.au/logout
	private boolean enableSsoLogout = false;	// Flag indicating if Single Sign Out is enabled
	private TicketValidator ticketValidator;	// Validates CAS tickets for all login attempts
	private Template casTemplate;				// Velocity template for the CAS login

    {
        try {
            logger.debug(String.format("Resource Loader Path: %s", Velocity.getProperty(Velocity.FILE_RESOURCE_LOADER_PATH).toString()));
            casTemplate = Velocity.getTemplate("cas/interface.vm");

            // read CAS configuration
            JsonSimpleConfig config = new JsonSimpleConfig();
            enableSsoLogout = config.getBoolean(Boolean.FALSE, CAS_PLUGIN_ID, PROP_SSO_LOGOUT).booleanValue();
            String casServerUrl = config.getString("cas-server-url-not-specified", CAS_PLUGIN_ID, PROP_CAS_SERVER_URL);

            if (casServerUrl.endsWith("/")) {
	            casLoginUrl = casServerUrl + "login";
	            casLogoutUrl = casServerUrl + "logout";
            }
            else {
	            casLoginUrl = casServerUrl + "/login";
	            casLogoutUrl = casServerUrl + "/logout";
            }

            // create the ticket validator based on config values
            String ticketValidatorClass = config.getString(null, CAS_PLUGIN_ID, PROP_TICKET_VALIDATOR_CLASS);
            ticketValidator = createTicketValidator(ticketValidatorClass, casServerUrl);
        }
        catch (Exception ex) {
            logger.error("Error during class initialisation", ex);
        }
    }

    /**
     * Construct a CAS ticket validator using the provided class parameter. If there is a problem
     * creating the requested ticket validator class, a CAS 1.0 ticket validator is returned instead.
     * @param className The fully qualified name of the ticket validator class to instantiate 
     * @param casServerUrlPrefix URL prefix for the CAS server, e.g. https://cas.institution.ed.au/
     * @return The constructed ticket validator
     */
	private TicketValidator createTicketValidator(String className, String casServerUrlPrefix) {
		// try to construct the validator class passed in as a parameter
		if (CommonUtils.isNotBlank(className)) {
			try {
				final Class<TicketValidator> validatorClass = ReflectUtils.loadClass(className);
				return ReflectUtils.newInstance(validatorClass, casServerUrlPrefix);
			}
			catch (Exception ex) {
				logger.warn("Couldn't create ticket validator for class: " + className, ex);
			}
		}

		// backup plan: create a CAS 1.0 ticket validator
		// (assumes later CAS server versions are backwards compatible with 1.0 clients)
		return new Cas10TicketValidator(casServerUrlPrefix);
	}

    @Override
	public String getId() {
		return CAS_PLUGIN_ID;
	}

	@Override
	public String getLabel() {
		return "Login via CAS";
	}

	@Override
	public String getInterface(String ssoUrl) {
        logger.trace(String.format("ssoGetInterface: %s", ssoUrl));
        StringWriter sw = new StringWriter();
        VelocityContext vc = new VelocityContext();
        try {
            vc.put("cas_url", ssoUrl);
            casTemplate.merge(vc, sw);
        } catch (IOException e) {
            logger.error(e.getMessage(), e);
        }
        return sw.toString();
	}

	@Override
	public List<String> getRolesList(JsonSessionState session) {
		// CAS does not supply user role information
		return new ArrayList<String>();
		// should return Collections.emptyList(), but this currently breaks PortalSecurityManagerImpl
	}

	@Override
	public User getUserObject(JsonSessionState session) {
        GenericUser user = null;

        // if the user has already passed authenticated with CAS then
        // we return a filled-in User object, otherwise we return null.
        Object casUsername = session.get(CAS_USERNAME);
		if (casUsername != null) {
	        user = new GenericUser();
			user.setUsername((String) casUsername);
			user.setSource(CAS_PLUGIN_ID);
        }

        logger.trace("getUserObject, User: " + toString(user));
		return user;
	}

	private String toString(GenericUser user) {
		return user == null ? "" : "(username: " + user.getUsername() + ", source: " + user.getSource() + ")";
	}

	@Override
	public void logout(JsonSessionState session) {
        logger.trace("logout, current user: " + session.get(CAS_USERNAME));
		clearUserLoginDetailsFromSession(session);
	}

	@Override
	public void ssoInit(JsonSessionState session, HttpServletRequest request) throws Exception {
		// save the CAS ticket (required to validate user login in ssoCheckUserDetails)
        logger.trace("ssoInit, saving CAS ticket into session");
        session.set(CAS_TICKET, request.getParameter(CAS_TICKET_HTTP_HEADER));
	}

	/**
	 * Remove any saved user login details from the session
	 * @param session The server session data
	 */
	private void clearUserLoginDetailsFromSession(JsonSessionState session) {
		session.remove(CAS_TICKET);
		session.remove(CAS_USERNAME);
	}

	@Override
	public void ssoCheckUserDetails(JsonSessionState session) {
		Object sessionUsername = session.get(CAS_USERNAME);
		if (sessionUsername == null || ((String) sessionUsername).length() == 0) {
			// we don't already have the user's login details in the session
			String ticket = (String) session.get(CAS_TICKET);
	        String returnAddress = (String) session.get(RETURN_ADDRESS);
	        logger.trace("ssoCheckUserDetails, CAS ticket: " + ticket);

	        try {
	        	// check the CAS ticket
	        	Assertion assertion = ticketValidator.validate(ticket, returnAddress);
	        	String username = assertion.getPrincipal().getName();
	        	logger.trace("ssoCheckUserDetails, username: " + username);
	        	session.set(CAS_USERNAME, username);
	        }
	        catch (TicketValidationException ex) {
	        	logger.debug("Failed to validate CAS ticket: ", ex.getMessage());
	        }
		}
		else {
	        logger.trace("ssoCheckUserDetails, user '" + sessionUsername + "' is already logged in");
		}
	}

	@Override
	public String ssoGetRemoteLogonURL(JsonSessionState session) {
        String returnAddress = (String) session.get(RETURN_ADDRESS);

		// construct CAS login URL, using the return address as the service URL
        String remoteUrl = CommonUtils.constructRedirectUrl(casLoginUrl, "service", returnAddress, false, false);
        logger.trace("ssoGetRemoteLogonURL, Remote Logon URL: " + remoteUrl);

        return remoteUrl;
	}

	public String ssoGetRemoteLogoutURL(JsonSessionState session) {
		if (enableSsoLogout) {
	        String returnAddress = (String) session.get(RETURN_ADDRESS);

			// construct CAS logout URL, using the return address as the service URL
	        String remoteUrl = CommonUtils.constructRedirectUrl(casLogoutUrl, "service", returnAddress, false, false);
	        logger.trace("ssoGetRemoteLogoutURL, Remote Logout URL: " + remoteUrl);

	        return remoteUrl;
		}
		else {
	        logger.trace("ssoGetRemoteLogoutURL, CAS logout disabled by configuration, returning null");
			return null;
		}
	}

	@Override
	public void ssoPrepareLogin(JsonSessionState session, String returnAddress, String server) throws Exception {
        logger.trace("ssoPrepareLogin, Return Address: " + returnAddress + " ; Server: " + server);
        session.set(RETURN_ADDRESS, returnAddress);
	}

}
